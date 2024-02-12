#include "loop.hpp"

namespace llarp
{
    static auto logcat = log::Cat("EventLoop");

    void Repeater::start(const loop_ptr& _loop, loop_time _interval, std::function<void()> task)
    {
        f = std::move(task);
        interval = loop_time_to_timeval(_interval);

        ev.reset(event_new(
            _loop.get(),
            -1,
            0,
            [](evutil_socket_t, short, void* s) {
                auto& self = *static_cast<Repeater*>(s);
                // execute callback
                self.f();
                // reset timer
                event_add(self.ev.get(), &self.interval);
            },
            this));

        event_add(ev.get(), &interval);
    }

    Repeater::~Repeater()
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
#ifdef __linux__
        //
#else
        //
#endif
    }

    void EventLoop::add_oneshot_event(loop_time delay, std::function<void()> hook)
    {
        auto tv = loop_time_to_timeval(delay);

        one_off = std::move(hook);

        event_base_once(
            loop().get(),
            -1,
            0,
            [](evutil_socket_t, short, void* self) {
                auto& ev = *static_cast<EventLoop*>(self);

                if (ev.one_off)
                {
                    ev.one_off();
                    ev.one_off = nullptr;
                }
            },
            this,
            &tv);
    }

    std::shared_ptr<Repeater> EventLoop::make_repeater()
    {
        return std::make_shared<Repeater>();
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

}  //  namespace llarp
