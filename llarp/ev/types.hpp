#pragma once

#include "loop.hpp"

namespace llarp
{
    /** EventTrigger
            This class is a parallel implementation of libquic Ticker (typedef'ed as 'EventTicker' in llarp/ev/loop);
        rather than invoking at regular intervals, it is manually invoked with an optional time delay. This is a useful
        functionality that allows us to manage events that are repeated, but not necessarily at fixed intervals; one
        example is lokinet instance bootstrapping (both client and relay), initial RouterID fetching, etc

            In the case of bootstrapping, the EventTrigger will execute the attempted bootstrap logic `n` times (which
        will be given a value of 5) with a 30s cooldown between sets of 5. Once the logic succeeds, it will set
        `::_proceed = false`, indicating that the EventTrigger should stop. If the local instane requires re-starting
        its bootstrap process for some reason, it can invoke `::resume()` to restart the logic.
    */
    struct EventTrigger
    {
      private:
        EventTrigger(const loop_ptr& _loop, std::chrono::microseconds _cooldown, std::function<void()> task, int _n);

      public:
        static std::shared_ptr<EventTrigger> make(
            const std::shared_ptr<EventLoop>& _loop,
            std::chrono::microseconds _cooldown,
            std::function<void()> task,
            int _n);

        // No move/copy/etc
        EventTrigger() = delete;
        EventTrigger(const EventTrigger&) = delete;
        EventTrigger(EventTrigger&&) = delete;
        EventTrigger& operator=(const EventTrigger&) = delete;
        EventTrigger& operator=(EventTrigger&&) = delete;

        ~EventTrigger();

        // TODO: maybe this should be private and only called internally
        // Invokes the function `f`, incrementing `::current` up to `n` before cooling down
        void fire();

        // TODO: rethink this part of the API
        // Resumes iterative execution
        void resume();

      private:
        int n;
        std::atomic<int> current{0};

        event_ptr ev;
        timeval cooldown;
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
}  //  namespace llarp

/**
    Notes:
    - Methods:
        - ::fire()
            - invoke stored callback
        - ::

    - Key functionalities:
        - number of executions before cooling down
        - cooldown (::call_later)
        - callback must be able to signal termination from within

 */
