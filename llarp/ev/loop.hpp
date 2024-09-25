#pragma once

#include "types.hpp"

#include <llarp/address/ip_packet.hpp>
#include <llarp/net/interface_info.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/thread/threading.hpp>
#include <llarp/util/time.hpp>

namespace llarp
{
    namespace vpn
    {
        class NetworkInterface;
    }  // namespace vpn

    class EventLoop
    {
        EventLoop();

        std::atomic<bool> _close_immediately{false};

      public:
        static std::shared_ptr<EventLoop> make();

        ~EventLoop();

        std::shared_ptr<oxen::quic::Loop> _loop;

        void set_close_immediate(bool b) { _close_immediately.store(b); }

        const loop_ptr& loop() const { return _loop->loop(); }

        bool in_event_loop() const { return _loop->in_event_loop(); }

        std::shared_ptr<FDPoller> add_network_interface(
            std::shared_ptr<vpn::NetworkInterface> netif, std::function<void()> hook);

        template <typename Callable>
        void call(Callable&& f)
        {
            _loop->call(std::forward<Callable>(f));
        }

        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            return _loop->call_get(std::forward<Callable>(f));
        }

        template <typename Callable>
        void call_soon(Callable&& f)
        {
            _loop->call_soon(std::forward<Callable>(f));
        }

        template <typename Callable>
        void call_later(loop_time delay, Callable&& hook)
        {
            _loop->call_later(delay, std::forward<Callable>(hook));
        }

        template <typename Callable>
        [[nodiscard]] std::shared_ptr<EventTicker> call_every(
            loop_time interval, Callable&& f, bool start_immediately = true, bool fixed_interval = false)
        {
            return _loop->call_every(interval, std::forward<Callable>(f), start_immediately, fixed_interval);
        }

        // Returns a pointer deleter that defers invocation of a custom deleter to the event loop
        template <typename T, typename Callable>
        auto wrapped_deleter(Callable&& f)
        {
            return _loop->template wrapped_deleter<T>(std::forward<Callable>(f));
        }

        // Similar in concept to std::make_shared<T>, but it creates the shared pointer with a
        // custom deleter that dispatches actual object destruction to the network's event loop for
        // thread safety.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            return _loop->template make_shared<T>(std::forward<Args>(args)...);
        }

        // Similar to the above make_shared, but instead of forwarding arguments for the
        // construction of the object, it creates the shared_ptr from the already created object ptr
        // and wraps the object's deleter in a wrapped_deleter
        template <typename T, typename Callable>
        std::shared_ptr<T> shared_ptr(T* obj, Callable&& deleter)
        {
            return _loop->template shared_ptr<T, Callable>(obj, std::forward<Callable>(deleter));
        }

        template <typename Callable>
        auto make_caller(Callable&& f)
        {
            return [this, f = std::forward<Callable>(f)](auto&&... args) {
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

        void stop(bool immediate = false);
    };
}  //  namespace llarp
