#include "types.hpp"

namespace llarp
{
    static auto logcat = llarp::log::Cat("ev-trigger");

    std::shared_ptr<EventTrigger> EventTrigger::make(
        const std::shared_ptr<EventLoop>& _loop,
        std::chrono::microseconds _cooldown,
        std::function<void()> task,
        int _n)
    {
        auto evt = _loop->template make_shared<EventTrigger>(_loop->loop(), _cooldown, std::move(task), _n);
        return evt;
    }

    EventTrigger::EventTrigger(
        const loop_ptr& _loop, std::chrono::microseconds _cooldown, std::function<void()> task, int _n)
        : n{_n}, cooldown{loop_time_to_timeval(_cooldown)}, f{std::move(task)}
    {
        ev.reset(event_new(
            _loop.get(),
            -1,
            0,
            [](evutil_socket_t, short, void* s) {
                try
                {
                    auto* self = reinterpret_cast<EventTrigger*>(s);
                    assert(self);

                    if (not self->f)
                    {
                        log::critical(logcat, "EventTrigger does not have a callback to execute!");
                        return;
                    }

                    if (not self->_proceed)
                    {
                        log::critical(logcat, "EventTrigger attempting to execute finished event!");
                        return;
                    }

                    // execute callback
                    self->f();
                }
                catch (const std::exception& e)
                {
                    log::critical(logcat, "EventTrigger caught exception: {}", e.what());
                }
            },
            this));
    }

    EventTrigger::~EventTrigger()
    {
        ev.reset();
        f = nullptr;
    }

    void EventTrigger::fire()
    {
        event_active(ev.get(), 0, 0);
    }
}  //  namespace llarp
