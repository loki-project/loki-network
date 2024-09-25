#include "loop.hpp"

#include <llarp/vpn/platform.hpp>

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

    std::shared_ptr<FDPoller> EventLoop::add_network_interface(
        std::shared_ptr<vpn::NetworkInterface> netif, std::function<void()> hook)
    {
        (void)netif;
        (void)hook;
        std::shared_ptr<FDPoller> _p;

#ifdef __linux__
        _p = _loop->template make_shared<LinuxPoller>(netif->PollFD(), _loop->loop(), std::move(hook));
#else
        //
#endif
        return _p;
    }

    void EventLoop::stop(bool)
    {
        // _loop->shutdown(immediate);
    }

}  //  namespace llarp
