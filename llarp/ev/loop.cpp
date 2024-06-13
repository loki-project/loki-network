#include "loop.hpp"

namespace llarp
{
    static auto logcat = log::Cat("EventLoop");

    std::shared_ptr<EventLoop> EventLoop::make(std::promise<void> p)
    {
        return std::shared_ptr<EventLoop>{new EventLoop{std::move(p)}};
    }

    // std::shared_ptr<EventLoop> EventLoop::make(loop_ptr loop_ptr, std::thread::id loop_thread_id)
    // {
    //     return std::shared_ptr<EventLoop>{new EventLoop{std::move(loop_ptr), loop_thread_id}};
    // }

    EventLoop::EventLoop(std::promise<void> p)
        : _close_promise{std::make_unique<std::promise<void>>(std::move(p))},
          _loop{std::make_shared<oxen::quic::Loop>()}
    {}

    EventLoop::EventLoop(loop_ptr loop_ptr, std::thread::id thread_id)
        : _loop{std::make_shared<oxen::quic::Loop>(std::move(loop_ptr), thread_id)}
    {}

    EventLoop::~EventLoop()
    {
        log::info(logcat, "Shutting down lokinet loop {}", _close_immediately ? "ASAP" : "gracefully");

        _loop->shutdown(_close_immediately);

        if (_close_promise)
        {
            _close_promise->set_value();
            _close_promise.reset();
        }
    }

    bool EventLoop::add_network_interface(std::shared_ptr<vpn::NetworkInterface> netif, ip_pkt_hook handler)
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

    void EventLoop::stop(bool immediate)
    {
        _loop->shutdown(immediate);

        if (_close_promise)
        {
            _close_promise->set_value();
            _close_promise.reset();
        }
    }

}  //  namespace llarp
