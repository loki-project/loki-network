#include "ev.hpp"

#include "libuv.hpp"

#include <llarp/net/net.hpp>

#include <cstddef>

namespace llarp
{
    std::shared_ptr<EventLoop> EventLoop::create(size_t queueLength)
    {
        return std::make_shared<llarp::uv::Loop>(queueLength);
    }

    const net::Platform* EventLoop::Net_ptr() const
    {
        return net::Platform::Default_ptr();
    }

}  // namespace llarp
