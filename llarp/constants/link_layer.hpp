#pragma once
#include <llarp/util/time.hpp>

#include <cstdlib>

constexpr size_t MAX_LINK_MSG_SIZE = 8192;
static constexpr auto DefaultLinkSessionLifetime = 5min;
constexpr size_t MaxSendQueueSize = 1024 * 16;
static constexpr auto LinkLayerConnectTimeout = 5s;

namespace llarp::constants
{
    static constexpr auto DefaultInboundIWPPort = uint16_t{1090};
}
