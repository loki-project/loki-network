#pragma once

#include "buffer.hpp"
#include "formattable.hpp"

#include <fmt/chrono.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <iostream>

using namespace std::chrono_literals;

namespace llarp
{
    // Libevent uses µs precision
    using loop_time = std::chrono::microseconds;

    using rc_time = std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds>;

    rc_time time_point_now();

    /// get time right now as milliseconds, this is monotonic
    std::chrono::milliseconds time_now_ms();

    /// get the uptime of the process
    std::chrono::milliseconds uptime();

    /// convert to milliseconds
    uint64_t to_milliseconds(std::chrono::milliseconds duration);

    nlohmann::json to_json(const std::chrono::milliseconds& t);

    // Returns a string such as "27m13s ago" or "in 1h12m" or "now".  You get precision of minutes
    // (for >=1h), seconds (>=10s), or milliseconds.  The `now_threshold` argument controls how
    // close to current time (default 1s) the time has to be to get the "now" argument.
    std::string short_time_from_now(
        const std::chrono::system_clock::time_point& t, const std::chrono::milliseconds& now_threshold = 1s);

    inline timeval loop_time_to_timeval(loop_time t)
    {
        return timeval{
            .tv_sec = static_cast<decltype(timeval::tv_sec)>(t / 1s),
            .tv_usec = static_cast<decltype(timeval::tv_usec)>((t % 1s) / 1us)};
    }

    std::chrono::nanoseconds get_timestamp();

    template <typename unit_t>
    auto get_timestamp()
    {
        return std::chrono::duration_cast<unit_t>(get_timestamp());
    }

}  // namespace llarp
