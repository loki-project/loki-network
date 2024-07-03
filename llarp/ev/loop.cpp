#include "loop.hpp"

namespace llarp
{
    static auto logcat = log::Cat("EventLoop");

    std::shared_ptr<EventLoop> EventLoop::make()
    {
        return std::shared_ptr<EventLoop>{new EventLoop{}};
    }

    // std::shared_ptr<EventLoop> EventLoop::make(loop_ptr loop_ptr, std::thread::id loop_thread_id)
    // {
    //     return std::shared_ptr<EventLoop>{new EventLoop{std::move(loop_ptr), loop_thread_id}};
    // }

    EventLoop::EventLoop() : _loop{std::make_shared<oxen::quic::Loop>()} {}

    EventLoop::EventLoop(loop_ptr loop_ptr, std::thread::id thread_id)
        : _loop{std::make_shared<oxen::quic::Loop>(std::move(loop_ptr), thread_id)}
    {}

    EventLoop::~EventLoop()
    {
        log::info(logcat, "Shutting down lokinet loop {}", _close_immediately ? "ASAP" : "gracefully");

        _loop->shutdown(_close_immediately);
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
    }

}  //  namespace llarp
