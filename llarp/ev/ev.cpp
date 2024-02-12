#include "ev.hpp"

#include "libuv.hpp"

#include <llarp/net/net.hpp>

#include <cstddef>

namespace llarp
{
    std::shared_ptr<EvLoop_deprecated> EvLoop_deprecated::create(size_t queueLength)
    {
        return std::make_shared<llarp::uv::uvwLoop>(queueLength);
    }

    const net::Platform* EvLoop_deprecated::net_ptr() const
    {
        return net::Platform::Default_ptr();
    }

}  // namespace llarp
