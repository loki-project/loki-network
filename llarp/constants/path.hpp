#pragma once

#include <llarp/util/time.hpp>

#include <chrono>
#include <cstddef>

namespace llarp::path
{
    /// maximum path length
    constexpr std::size_t MAX_LEN = 8;
    /// default path length
    constexpr std::size_t DEFAULT_LEN = 4;
    /// pad messages to the nearest this many bytes
    constexpr std::size_t PAD_SIZE = 128;
    /// default path lifetime in ms
    constexpr std::chrono::milliseconds DEFAULT_LIFETIME = 20min;
    /// minimum intro lifetime we will advertise
    constexpr std::chrono::milliseconds MIN_INTRO_LIFETIME = DEFAULT_LIFETIME / 2;
    /// number of slices of path lifetime to spread intros out via
    constexpr auto INTRO_SPREAD_SLICES = 4;
    /// spacing frequency at which we try to build paths for introductions
    constexpr std::chrono::milliseconds INTRO_PATH_SPREAD = DEFAULT_LIFETIME / INTRO_SPREAD_SLICES;
    /// how long away from expiration in millseconds do we consider an intro to become stale
    constexpr std::chrono::milliseconds INTRO_STALE_THRESHOLD = DEFAULT_LIFETIME - INTRO_PATH_SPREAD;
    /// Minimum paths to keep around for intros; mainly used at startup (the
    /// spread, above, should be able to maintain more than this number of paths
    /// normally once things are going).
    constexpr std::size_t MIN_INTRO_PATHS = 4;
    /// after this many ms a path build times out
    constexpr auto BUILD_TIMEOUT = 10s;

    /// measure latency every this interval ms
    constexpr auto LATENCY_INTERVAL = 20s;
    /// if a path is inactive for this amount of time it's dead
    constexpr auto ALIVE_TIMEOUT = LATENCY_INTERVAL * 1.5;

    /// how big transit hop traffic queues are
    constexpr std::size_t TRANSIT_HOP_QUEUE_SIZE = 256;

}  // namespace llarp::path
