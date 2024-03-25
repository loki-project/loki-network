#pragma once

#include <nlohmann/json.hpp>
#include <oxen/log/format.hpp>

#include <chrono>
#include <cstdint>
#include <string>

namespace llarp
{
    using namespace std::literals;
    using namespace oxen::log::literals;

    /// convert to milliseconds
    uint64_t to_milliseconds(std::chrono::milliseconds duration);

    using DateClock_t = std::chrono::system_clock;
    using TimePoint_t = DateClock_t::time_point;

    using StatusObject = nlohmann::json;
}  // namespace llarp
