#pragma once

#include <nlohmann/json.hpp>
#include <oxen/log/format.hpp>

#include <chrono>
#include <cstdint>
#include <string>

// using uint8_t = uint8_t;

namespace llarp
{
    using Duration_t = std::chrono::milliseconds;
    using namespace std::literals;
    using namespace oxen::log::literals;

    /// convert to milliseconds
    uint64_t ToMS(Duration_t duration);

    using DateClock_t = std::chrono::system_clock;
    using TimePoint_t = DateClock_t::time_point;

    using StatusObject = nlohmann::json;
}  // namespace llarp

using llarp_time_t = llarp::Duration_t;
