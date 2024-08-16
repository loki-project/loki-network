#include "loop.hpp"

namespace llarp
{
    static auto logcat = log::Cat("EventLoop");

    std::shared_ptr<EventLoop> EventLoop::make()
    {
        return std::shared_ptr<EventLoop>{new EventLoop{}};
    }

    EventLoop::EventLoop() : _loop{std::make_shared<oxen::quic::Loop>()} {}

    EventLoop::~EventLoop()
    {
        // _loop->shutdown(_close_immediately);
        log::info(logcat, "lokinet loop shut down {}", _close_immediately ? "immediately" : "gracefully");
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

    void EventLoop::stop(bool)
    {
        // _loop->shutdown(immediate);
    }

}  //  namespace llarp
