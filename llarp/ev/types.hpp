#pragma once

#include <oxen/quic.hpp>

extern "C"
{
#include <event2/watch.h>
}

namespace llarp
{
    using namespace std::chrono_literals;

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

    /** FDPoller
            This class is the base for the platform-specific Pollers that watch for IO on the virtual TUN network
        interface.
     */
    struct FDPoller
    {
        friend class oxen::quic::Loop;

        // No move/copy/etc
        FDPoller() = delete;
        FDPoller(const FDPoller&) = delete;
        FDPoller(FDPoller&&) = delete;
        FDPoller& operator=(const FDPoller&) = delete;
        FDPoller& operator=(FDPoller&&) = delete;

        virtual ~FDPoller()
        {
            ev.reset();
            f = nullptr;
        }

      protected:
        FDPoller(int _fd, std::function<void()> task) : fd{_fd}, f{std::move(task)} {}

        int fd;
        event_ptr ev;
        std::function<void()> f;

      public:
        virtual bool start() = 0;

        virtual bool stop() = 0;
    };

    /** LinuxPoller
            This class is a linux-specific extension of the Base poller type.
     */
    struct LinuxPoller final : public FDPoller
    {
        friend class EventLoop;
        friend class oxen::quic::Loop;

      private:
        LinuxPoller(int _fd, const loop_ptr& _loop, std::function<void()> task);

      public:
        bool start() override;

        bool stop() override;
    };

}  //  namespace llarp
