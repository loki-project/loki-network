#pragma once

#include <array>
#include <cstdint>

namespace llarp
{
    // Given a full lokinet version of: lokinet-1.2.3-abc these are:
    extern const std::array<uint8_t, 3> LOKINET_VERSION;
    extern const char* const LOKINET_VERSION_TAG;
    extern const char* const LOKINET_VERSION_FULL;

    extern const char* const LOKINET_DEFAULT_NETID;
    extern const char* const LOKINET_TESTNET_NETID;
}  // namespace llarp
