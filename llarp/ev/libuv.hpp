#pragma once
#include "ev.hpp"
#include "udp_handle.hpp"

#include <llarp/util/thread/queue.hpp>

#include <uvw.hpp>

#include <functional>
#include <map>
#include <vector>

namespace llarp::uv
{
    class UVWakeup;
    class UVRepeater;

    class Loop : public llarp::EventLoop
    {
       public:
        using Callback = std::function<void()>;

        Loop(size_t queue_size);

        virtual void run() override;

        bool running() const override;

        llarp_time_t time_now() const override
        {
            return m_Impl->now();
        }

        void call_later(llarp_time_t delay_ms, std::function<void(void)> callback) override;

        void tick_event_loop();

        void stop() override;

        bool add_ticker(std::function<void(void)> ticker) override;

        bool add_network_interface(
            std::shared_ptr<llarp::vpn::NetworkInterface> netif,
            std::function<void(llarp::net::IPPacket)> handler) override;

        void call_soon(std::function<void(void)> f) override;

        std::shared_ptr<llarp::EventLoopWakeup> make_waker(std::function<void()> callback) override;

        std::shared_ptr<EventLoopRepeater> make_repeater() override;

        virtual std::shared_ptr<llarp::UDPHandle> make_udp(UDPReceiveFunc on_recv) override;

        void FlushLogic();

        std::shared_ptr<uvw::Loop> MaybeGetUVWLoop() override;

        bool inEventLoop() const override;

       protected:
        std::shared_ptr<uvw::Loop> m_Impl;
        std::optional<std::thread::id> m_EventLoopThreadID;

       private:
        std::shared_ptr<uvw::AsyncHandle> m_WakeUp;
        std::atomic<bool> m_Run;
        using AtomicQueue_t = llarp::thread::Queue<std::function<void(void)>>;
        AtomicQueue_t m_LogicCalls;

#ifdef LOKINET_DEBUG
        uint64_t last_time;
        uint64_t loop_run_count;
#endif
        std::atomic<uint32_t> m_nextID;

        std::map<uint32_t, Callback> m_pendingCalls;

        std::unordered_map<int, std::shared_ptr<uvw::PollHandle>> m_Polls;

        void wakeup() override;
    };

}  // namespace llarp::uv
