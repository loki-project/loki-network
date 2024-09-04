#pragma once

#include <oxen/quic.hpp>

extern "C"
{
#include <event2/visibility.h>
}

namespace llarp
{
    class EventLoop;

    using event_ptr = oxen::quic::event_ptr;
    using EventTicker = oxen::quic::Ticker;

    // shared_ptr containing the actual libev loop
    using loop_ptr = std::shared_ptr<::event_base>;

    /** EventTrigger
            This class is a parallel implementation of libquic Ticker (typedef'ed as 'EventTicker' above). Rather than
        invoking at regular intervals, it is manually invoked with an optional time delay. This is a useful
        functionality that allows us to manage events that are repeated, but not necessarily at fixed intervals; one
        example is lokinet instance bootstrapping (both client and relay), initial RouterID fetching, etc

            In the case of bootstrapping, the EventTrigger will execute the attempted bootstrap logic `n` times (which
        will be given a value of 5) with a 30s cooldown between sets of 5. Once the logic succeeds, it will set
        `::_proceed = false`, indicating that the EventTrigger should stop. If the local instane requires re-starting
        its bootstrap process for some reason, it can invoke `::resume()` to restart the logic.
    */
    struct EventTrigger
    {
        // Allows the libquic loop object to call the private constructor when constructing the shared pointer with
        // the loop deleter
        friend class oxen::quic::Loop;

      private:
        EventTrigger(
            const loop_ptr& _loop,
            std::chrono::microseconds _cooldown,
            std::function<void()> task,
            int _n,
            bool start_immediately);

      public:
        static std::shared_ptr<EventTrigger> make(
            const std::shared_ptr<EventLoop>& _loop,
            std::chrono::microseconds _cooldown,
            std::function<void()> task,
            int _n,
            bool start_immediately = false);

        // No move/copy/etc
        EventTrigger() = delete;
        EventTrigger(const EventTrigger&) = delete;
        EventTrigger(EventTrigger&&) = delete;
        EventTrigger& operator=(const EventTrigger&) = delete;
        EventTrigger& operator=(EventTrigger&&) = delete;

        ~EventTrigger();

        // Resumes iterative execution after successfully cooling down or being signalled to stop by the callback
        bool begin();

        // Called by the passed callback to signal that the iterative invocation should STOP
        bool halt();

      private:
        // Invokes the function `f`, incrementing `::current` up to `n` before cooling down
        void fire();

        // Awaits further execution for `_cooldown` amount of time
        void cooldown();

        const int n;
        std::atomic<int> _current{0};

        event_ptr ev;
        event_ptr cv;
        const timeval _cooldown;
        const timeval _null_tv{};
        std::function<void()> f;

        std::atomic<bool> _is_cooling_down{false};
        std::atomic<bool> _is_iterating{false};

        // Internal boolean for the callback to signal execution should be stopped after the current iteration
        std::atomic<bool> _proceed{true};

      public:
        // Indicates the EventTrigger is invoking its callback `n` number of times. During one of these iterations,
        // the callback may signal termination of iteration by setting `::_proceed = false`
        bool is_iterating() const { return _is_iterating; }

        // Indicates the EventTrigger has just invoked its callback `n` number of times, and is now awaiting its next
        // attempt at execution (which will be in `::cooldown` amount of time)
        bool is_cooling_down() const { return _is_cooling_down; }
    };

    /** EventPoller
            This class is a similar implementation to EventTrigger and Ticker, with a few key differences in relation to
        the net interfaces it manages. First, we don't want the execution of the logic to be tied to a specific timer or
        fixed interval. Rather, this will be event triggered on packet I/O. As a result, this necessitates the second
        key difference: it uses a libevent "prepare" watcher to fire immediately BEFORE polling for I/O. Libevent also
        exposes the concept of a "check" watcher, which fires immediately AFTER processing active events.
     */
    struct EventPoller
    {
        friend class oxen::quic::Loop;

      private:
        EventPoller(const loop_ptr& _loop, std::function<void()> task)
        {
            evwatch_prepare_new(_loop.get(), nullptr, nullptr);
        }

      public:
        static std::shared_ptr<EventPoller> make(const loop_ptr& _loop, std::function<void()> task);
    };

}  //  namespace llarp
