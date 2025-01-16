#include "types.hpp"

#include "loop.hpp"

namespace llarp
{
    static auto logcat = llarp::log::Cat("ev-trigger");

    std::shared_ptr<EventTrigger> EventTrigger::make(
        const std::shared_ptr<EventLoop>& _loop,
        std::chrono::microseconds _cooldown,
        std::function<void()> task,
        int _n,
        bool start_immediately)
    {
        return _loop->template make_shared<EventTrigger>(
            _loop->loop(), _cooldown, std::move(task), _n, start_immediately);
    }

    EventTrigger::EventTrigger(
        const loop_ptr& _loop,
        std::chrono::microseconds _cooldown,
        std::function<void()> task,
        int _n,
        bool start_immediately)
        : n{_n}, _cooldown{loop_time_to_timeval(_cooldown)}, f{std::move(task)}
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

                    if (self->_is_cooling_down)
                    {
                        log::critical(logcat, "EventTrigger attempting to execute cooling down event!");
                        return;
                    }

                    if (not self->_is_iterating)
                    {
                        log::critical(logcat, "EventTrigger attempting to execute finished event!");
                        return;
                    }

                    log::debug(logcat, "EventTrigger executing callback...");
                    self->fire();
                }
                catch (const std::exception& e)
                {
                    log::critical(logcat, "EventTrigger caught exception: {}", e.what());
                }
            },
            this));

        cv.reset(event_new(
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

                    if (not self->_is_cooling_down)
                    {
                        log::critical(logcat, "EventTrigger attempting to resume when it is NOT cooling down!");
                        return;
                    }

                    if (not self->_is_iterating)
                    {
                        log::critical(logcat, "EventTrigger attempting to resume when it is halted!");
                        return;
                    }

                    log::info(logcat, "EventTrigger resuming callback iteration...");
                    self->start();
                }
                catch (const std::exception& e)
                {
                    log::critical(logcat, "EventTrigger caught exception: {}", e.what());
                }
            },
            this));

        if (start_immediately)
        {
            auto rv = start();
            log::debug(logcat, "EventTrigger started {}successfully!", rv ? "" : "un");
        }
    }

    EventTrigger::~EventTrigger()
    {
        ev.reset();
        f = nullptr;
    }

    void EventTrigger::fire()
    {
        if (_current < n)
        {
            _current += 1;

            log::debug(logcat, "Attempting callback {}/{} times!", _current.load(), n);
            f();
        }

        if (_current == n)
        {
            log::debug(logcat, "Callback attempted {} times! Cooling down...", n);
            return cooldown();
        }

        event_del(ev.get());
        event_add(ev.get(), &_null_tv);
    }

    bool EventTrigger::stop()
    {
        _is_cooling_down = false;
        _is_iterating = false;
        _proceed = false;

        bool ret = event_del(ev.get()) == 0;
        ret &= event_del(cv.get()) == 0;
        log::debug(logcat, "EventTrigger halted {}successfully!", ret ? "" : "un");

        return ret;
    }

    bool EventTrigger::start()
    {
        _is_cooling_down = false;
        _is_iterating = true;
        _proceed = true;
        _current = 0;

        auto rv = event_add(ev.get(), &_null_tv);
        log::debug(logcat, "EventTrigger begun {}successfully!", rv == 0 ? "" : "un");

        return rv == 0;
    }

    void EventTrigger::cooldown()
    {
        event_del(ev.get());

        _is_cooling_down = event_add(cv.get(), &_cooldown) == 0;

        log::trace(logcat, "Cooldown {}successfully began after {} attempts!", _is_cooling_down ? "" : "un", _current);
    }

    LinuxPoller::LinuxPoller(int _fd, const loop_ptr& _loop, std::function<void()> task)
        : FDPoller{_fd, std::move(task)}
    {
        ev.reset(event_new(
            _loop.get(),
            fd,
            EV_READ | EV_PERSIST,
            [](evutil_socket_t, short, void* s) {
                try
                {
                    auto* self = reinterpret_cast<LinuxPoller*>(s);
                    assert(self);

                    if (not self->f)
                    {
                        log::critical(logcat, "EventPoller does not have a callback to execute!");
                        return;
                    }

                    self->f();
                }
                catch (const std::exception& e)
                {
                    log::critical(logcat, "EventPoller caught exception: {}", e.what());
                }
            },
            this));

        log::debug(logcat, "Linux poller configured to watch FD {}", fd);
    }

    bool LinuxPoller::start()
    {
        auto rv = event_add(ev.get(), nullptr) == 0;
        log::info(logcat, "Linux poller {} watching FD {}", rv ? "successfully began" : "failed to start", fd);
        return rv;
    }

    bool LinuxPoller::stop()
    {
        auto rv = event_del(ev.get());
        log::info(logcat, "Linux poller {} watching FD {}", rv ? "successfully stopped" : "failed to stop", fd);
        return rv;
    }
}  //  namespace llarp
