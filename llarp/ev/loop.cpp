#include "loop.hpp"

namespace llarp
{
    static auto logcat = log::Cat("EventLoop");

    void EventHandler::start(const loop_ptr& _loop, loop_time _interval, std::function<void()> task, bool _repeat)
    {
        f = std::move(task);
        interval = loop_time_to_timeval(_interval);
        repeat = _repeat;

        ev.reset(event_new(
            _loop.get(),
            -1,
            0,
            [](evutil_socket_t, short, void* s) {
                auto& self = *static_cast<EventHandler*>(s);
                // execute callback
                self.f();
                // should repeat?
                if (self.repeat)
                    event_add(self.ev.get(), &self.interval);
            },
            this));

        event_add(ev.get(), &interval);
    }

    EventHandler::~EventHandler()
    {
        ev.reset();
        f = nullptr;
    }

    std::shared_ptr<EventLoop> EventLoop::make()
    {
        return std::make_shared<EventLoop>();
    }

    std::shared_ptr<EventLoop> EventLoop::make(loop_ptr loop_ptr, std::thread::id loop_thread_id)
    {
        return std::make_shared<EventLoop>(std::move(loop_ptr), loop_thread_id);
    }

    EventLoop::EventLoop() : _loop{std::make_shared<oxen::quic::Loop>()}
    {}

    EventLoop::EventLoop(loop_ptr loop_ptr, std::thread::id thread_id)
        : _loop{std::make_shared<oxen::quic::Loop>(std::move(loop_ptr), thread_id)}
    {}

    bool EventLoop::add_network_interface(std::shared_ptr<vpn::NetworkInterface> netif, udp_pkt_hook handler)
    {
        (void)netif;
        (void)handler;

#ifdef __linux__
        //
#else
        //
#endif
        return true;
    }

    void EventLoop::add_oneshot_event(loop_time delay, std::function<void()> hook)
    {
        auto handler = make_handler();
        auto& h = *handler;

        h.start(loop(), delay, [hdnlr = std::move(handler), func = std::move(hook)]() mutable {
            func();
            hdnlr.reset();
        });
    }

    std::shared_ptr<EventHandler> EventLoop::make_handler()
    {
        return std::make_shared<EventHandler>();
    }

    void EventLoop::call_later(loop_time delay, std::function<void()> hook)
    {
        if (in_event_loop())
        {
            add_oneshot_event(delay, std::move(hook));
        }
        else
        {
            call_soon([this, func = std::move(hook), target_time = get_timestamp<loop_time>() + delay]() {
                auto updated_delay = target_time - get_timestamp<loop_time>();

                if (updated_delay <= 0us)
                    func();
                else
                    add_oneshot_event(updated_delay, std::move(func));
            });
        }
    }

    void EventLoop::stop(bool immediate)
    {
        _loop->shutdown(immediate);
    }

}  //  namespace llarp
