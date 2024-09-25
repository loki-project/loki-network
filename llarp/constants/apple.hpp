#pragma once

#include <cstdint>

namespace llarp::apple
{
    /// Localhost port on macOS where we proxy DNS requests *through* the tunnel, because without
    /// calling into special snowflake Apple network APIs an extension's network connections all go
    /// around the tunnel, even when the tunnel is (supposedly) the default route.
    inline constexpr std::uint16_t dns_trampoline_port = 1053;

    /// We query the above trampoline from unbound with this fixed source port (so that the
    /// trampoline is simplified by not having to track different ports for different requests).
    inline constexpr std::uint16_t dns_trampoline_source_port = 1054;
}  // namespace llarp::apple
