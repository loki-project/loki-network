#include "libuv.hpp"

#include <llarp/util/exceptions.hpp>
#include <llarp/vpn/platform.hpp>

#include <cstring>
#include <memory>
#include <thread>
#include <type_traits>

namespace llarp::uv
{
    std::shared_ptr<uvw::Loop> uvwLoop::MaybeGetUVWLoop()
    {
        return m_Impl;
    }

    class UVWakeup final : public EventLoopWakeup
    {
        std::shared_ptr<uvw::AsyncHandle> async;

       public:
        UVWakeup(uvw::Loop& loop, std::function<void()> callback) : async{loop.resource<uvw::AsyncHandle>()}
        {
            async->on<uvw::AsyncEvent>([f = std::move(callback)](auto&, auto&) { f(); });
        }

        void Trigger() override
        {
            async->send();
        }

        ~UVWakeup() override
        {
            async->close();
        }
    };

    class UVRepeater final : public EvLoopRepeater_deprecated
    {
        std::shared_ptr<uvw::TimerHandle> timer;

       public:
        UVRepeater(uvw::Loop& loop) : timer{loop.resource<uvw::TimerHandle>()}
        {}

        void start(llarp_time_t every, std::function<void()> task) override
        {
            timer->start(every, every);
            timer->on<uvw::TimerEvent>([task = std::move(task)](auto&, auto&) { task(); });
        }

        ~UVRepeater() override
        {
            timer->stop();
        }
    };

    struct UDPHandle_uvw final : llarp::UDPHandle_deprecated
    {
        UDPHandle_uvw(uvw::Loop& loop, ReceiveFunc rf);

        bool listen(const SockAddr_deprecated& addr) override;

        bool send(const SockAddr_deprecated& dest, const llarp_buffer_t& buf) override;

        std::optional<SockAddr_deprecated> LocalAddr() const override
        {
            if (auto addr = handle->sock<uvw::IPv4>(); not addr.ip.empty())
                return SockAddr_deprecated{addr.ip, huint16_t{static_cast<uint16_t>(addr.port)}};
            if (auto addr = handle->sock<uvw::IPv6>(); not addr.ip.empty())
                return SockAddr_deprecated{addr.ip, huint16_t{static_cast<uint16_t>(addr.port)}};
            return std::nullopt;
        }

        // UNUSED AS FUCK
        std::optional<int> file_descriptor() override
        {
#ifndef _WIN32
            if (int fd = handle->fd(); fd >= 0)
                return fd;
#endif
            return std::nullopt;
        }

        void close() override;

        ~UDPHandle_uvw() override;

       private:
        std::shared_ptr<uvw::UDPHandle> handle;

        void reset_handle(uvw::Loop& loop);
    };

    void uvwLoop::FlushLogic()
    {
        llarp::LogTrace("Loop::FlushLogic() start");
        while (not m_LogicCalls.empty())
        {
            auto f = m_LogicCalls.popFront();
            f();
        }
        llarp::LogTrace("Loop::FlushLogic() end");
    }

    void uvwLoop::tick_event_loop()
    {
        llarp::LogTrace("ticking event loop.");
        FlushLogic();
    }

    uvwLoop::uvwLoop(size_t queue_size) : llarp::EvLoop_deprecated{}, m_LogicCalls{queue_size}
    {
        if (!(m_Impl = uvw::Loop::create()))
            throw std::runtime_error{"Failed to construct libuv loop"};

#ifdef LOKINET_DEBUG
        last_time = 0;
        loop_run_count = 0;
#endif

#ifndef _WIN32
        signal(SIGPIPE, SIG_IGN);
#endif

        m_Run.store(true);
        m_nextID.store(0);
        if (!(m_WakeUp = m_Impl->resource<uvw::AsyncHandle>()))
            throw std::runtime_error{"Failed to create libuv async"};
        m_WakeUp->on<uvw::AsyncEvent>([this](const auto&, auto&) { tick_event_loop(); });
    }

    bool uvwLoop::running() const
    {
        return m_Run.load();
    }

    void uvwLoop::run()
    {
        llarp::LogTrace("Loop::run_loop()");
        m_EventLoopThreadID = std::this_thread::get_id();
        m_Impl->run();
        m_Impl->close();
        m_Impl.reset();
        llarp::LogInfo("we have stopped");
    }

    void uvwLoop::wakeup()
    {
        m_WakeUp->send();
    }

    std::shared_ptr<llarp::UDPHandle_deprecated> uvwLoop::make_udp(UDPReceiveFunc on_recv)
    {
        return std::static_pointer_cast<llarp::UDPHandle_deprecated>(
            std::make_shared<llarp::uv::UDPHandle_uvw>(*m_Impl, std::move(on_recv)));
    }

    static void setup_oneshot_timer(uvw::Loop& loop, llarp_time_t delay, std::function<void()> callback)
    {
        auto timer = loop.resource<uvw::TimerHandle>();
        timer->on<uvw::TimerEvent>([f = std::move(callback)](const auto&, auto& timer) {
            f();
            timer.stop();
            timer.close();
        });
        timer->start(delay, 0ms);
    }

    void uvwLoop::call_later(llarp_time_t delay_ms, std::function<void(void)> callback)
    {
        llarp::LogTrace("Loop::call_after_delay()");
#ifdef TESTNET_SPEED
        delay_ms *= TESTNET_SPEED;
#endif

        if (inEventLoop())
            setup_oneshot_timer(*m_Impl, delay_ms, std::move(callback));
        else
        {
            call_soon([this, f = std::move(callback), target_time = time_now() + delay_ms] {
                // Recalculate delay because it may have taken some time to get ourselves into the
                // logic thread
                auto updated_delay = target_time - time_now();
                if (updated_delay <= 0ms)
                    f();  // Timer already expired!
                else
                    setup_oneshot_timer(*m_Impl, updated_delay, std::move(f));
            });
        }
    }

    void uvwLoop::stop()
    {
        if (m_Run)
        {
            if (not inEventLoop())
                return call_soon([this] { stop(); });

            llarp::LogInfo("stopping event loop");
            m_Impl->walk([](auto&& handle) {
                if constexpr (!std::is_pointer_v<std::remove_reference_t<decltype(handle)>>)
                    handle.close();
            });
            llarp::LogDebug("Closed all handles, stopping the loop");
            m_Impl->stop();

            m_Run.store(false);
        }
    }

    bool uvwLoop::add_ticker(std::function<void(void)> func)
    {
        auto check = m_Impl->resource<uvw::CheckHandle>();
        check->on<uvw::CheckEvent>([f = std::move(func)](auto&, auto&) { f(); });
        check->start();
        return true;
    }

    bool uvwLoop::add_network_interface(
        std::shared_ptr<llarp::vpn::NetworkInterface> netif,
        std::function<void(llarp::net::IP_packet_deprecated)> handler)
    {
#ifdef __linux__
        using event_t = uvw::PollEvent;
        auto handle = m_Impl->resource<uvw::PollHandle>(netif->PollFD());
#else
        // we use a uv_prepare_t because it fires before blocking for new io events unconditionally
        // we want to match what linux does, using a uv_check_t does not suffice as the order of
        // operations is not what we need.
        using event_t = uvw::PrepareEvent;
        auto handle = m_Impl->resource<uvw::PrepareHandle>();
#endif

        if (!handle)
            return false;

        handle->on<event_t>(
            [netif = std::move(netif), handler = std::move(handler)](const event_t&, [[maybe_unused]] auto& handle) {
                for (auto pkt = netif->ReadNextPacket(); true; pkt = netif->ReadNextPacket())
                {
                    if (pkt.empty())
                        return;
                    if (handler)
                        handler(std::move(pkt));
                    // on windows/apple, vpn packet io does not happen as an io action that wakes up the
                    // event loop thus, we must manually wake up the event loop when we get a packet on
                    // our interface. on linux/android this is a nop
                    netif->MaybeWakeUpperLayers();
                }
            });

#ifdef __linux__
        handle->start(uvw::PollHandle::Event::READABLE);
#else
        handle->start();
#endif

        return true;
    }

    void uvwLoop::call_soon(std::function<void(void)> f)
    {
        if (not m_EventLoopThreadID.has_value())
        {
            m_LogicCalls.tryPushBack(f);
            m_WakeUp->send();
            return;
        }

        if (inEventLoop() and m_LogicCalls.full())
        {
            FlushLogic();
        }
        m_LogicCalls.pushBack(f);
        m_WakeUp->send();
    }

    // Sets `handle` to a new uvw UDP handle, first initiating a close and then disowning the handle
    // if already set, allocating the resource, and setting the receive event on it.
    void UDPHandle_uvw::reset_handle(uvw::Loop& loop)
    {
        if (handle)
            handle->close();
        handle = loop.resource<uvw::UDPHandle>();
        handle->on<uvw::UDPDataEvent>([this](auto& event, auto& /*handle*/) {
            on_recv(
                *this,
                SockAddr_deprecated{event.sender.ip, huint16_t{static_cast<uint16_t>(event.sender.port)}},
                OwnedBuffer{std::move(event.data), event.length});
        });
    }

    llarp::uv::UDPHandle_uvw::UDPHandle_uvw(uvw::Loop& loop, ReceiveFunc rf) : llarp::UDPHandle_deprecated{std::move(rf)}
    {
        reset_handle(loop);
    }

    bool UDPHandle_uvw::listen(const SockAddr_deprecated& addr)
    {
        if (handle->active())
            reset_handle(handle->loop());

        auto err = handle->on<uvw::ErrorEvent>([addr](auto& event, auto&) {
            throw llarp::util::bind_socket_error{
                fmt::format("failed to bind udp socket on {}: {}", addr, event.what())};
        });
        handle->bind(*static_cast<const sockaddr*>(addr));
        handle->recv();
        handle->erase(err);
        return true;
    }

    bool UDPHandle_uvw::send(const SockAddr_deprecated& to, const llarp_buffer_t& buf)
    {
        return handle->trySend(
                   *static_cast<const sockaddr*>(to),
                   const_cast<char*>(reinterpret_cast<const char*>(buf.base)),
                   buf.sz)
            >= 0;
    }

    void UDPHandle_uvw::close()
    {
        handle->close();
        handle.reset();
    }

    UDPHandle_uvw::~UDPHandle_uvw()
    {
        close();
    }

    std::shared_ptr<llarp::EventLoopWakeup> uvwLoop::make_waker(std::function<void()> callback)
    {
        return std::static_pointer_cast<llarp::EventLoopWakeup>(
            std::make_shared<UVWakeup>(*m_Impl, std::move(callback)));
    }

    std::shared_ptr<EvLoopRepeater_deprecated> uvwLoop::make_repeater()
    {
        return std::static_pointer_cast<EvLoopRepeater_deprecated>(std::make_shared<UVRepeater>(*m_Impl));
    }

    bool uvwLoop::inEventLoop() const
    {
        if (m_EventLoopThreadID)
            return *m_EventLoopThreadID == std::this_thread::get_id();
        // assume we are in it because we haven't started up yet
        return true;
    }

}  // namespace llarp::uv
