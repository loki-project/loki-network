#pragma once

#include "udp.hpp"

#include <llarp/net/interface_info.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/thread/threading.hpp>
#include <llarp/util/time.hpp>

#include <oxen/quic.hpp>

namespace llarp
{
    namespace vpn
    {
        class NetworkInterface;
    }  // namespace vpn

    class EventLoop;

    struct Repeater
    {
        event_ptr ev;
        timeval interval;
        std::function<void()> f;

        Repeater() = default;

        ~Repeater();

        void start(const loop_ptr& _loop, loop_time _interval, std::function<void()> task);
    };

    class EventLoop
    {
       public:
        static std::shared_ptr<EventLoop> make();
        static std::shared_ptr<EventLoop> make(loop_ptr loop_ptr, std::thread::id loop_thread_id);

        ~EventLoop();

       private:
        EventLoop();
        EventLoop(loop_ptr loop_ptr, std::thread::id loop_thread_id);

        std::shared_ptr<oxen::quic::Loop> _loop;
        event_ptr _ticker;

        // Libevent doesn't allow for lambda captures, so callbacks passed to ::call_later
        // are set here in structs to be called and then reset
        event_hook one_off = nullptr;

        void add_oneshot_event(loop_time delay, std::function<void()> hook);

        std::shared_ptr<Repeater> make_repeater();

       public:
        const loop_ptr& loop() const
        {
            return _loop->loop();
        }

        bool in_event_loop() const
        {
            return _loop->in_event_loop();
        }

        bool add_ticker(std::function<void()> ticker);

        bool add_network_interface(std::shared_ptr<vpn::NetworkInterface> netif, udp_pkt_hook handler);

        template <typename Callable>
        void call(Callable&& f, source_location src = source_location::current())
        {
            _loop->call(std::forward<Callable>(f), src);
        }

        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f, source_location src = source_location::current())
        {
            return _loop->call_get(std::forward<Callable>(f), src);
        }

        void call_soon(std::function<void(void)> f, source_location src = source_location::current())
        {
            _loop->call_soon(std::move(f), src);
        }

        void call_later(loop_time delay, std::function<void()> hook);

        template <typename Callable>
        void call_every(loop_time interval, std::weak_ptr<void> caller, Callable f)
        {
            auto repeater = make_repeater();
            // grab the reference before giving ownership of the repeater to the lambda
            auto& r = *repeater;
            r.start(
                loop(),
                interval,
                [rep = std::move(repeater), owner = std::move(caller), func = std::move(f)]() mutable {
                    if (auto ptr = owner.lock())
                        func();
                    else
                        rep.reset();
                });
        }

        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            return _loop->make_shared<T>(std::forward<Args>(args)...);
        }

        template <typename Callable>
        auto make_caller(Callable f)
        {
            return [this, f = std::move(f)](auto&&... args) {
                if (in_event_loop())
                    return f(std::forward<decltype(args)>(args)...);

                auto args_tuple_ptr = std::make_shared<std::tuple<std::decay_t<decltype(args)>...>>(
                    std::forward<decltype(args)>(args)...);

                call_soon([f, args = std::move(args_tuple_ptr)]() mutable {
                    // Moving away the tuple args here is okay because this lambda will only be invoked once
                    std::apply(f, std::move(*args));
                });
            };
        }

        void halt_events();

        void stop(bool immediate = false);

        void start();
    };
}  //  namespace llarp
