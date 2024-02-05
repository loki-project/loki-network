#pragma once

#include "types.hpp"

#include <fmt/chrono.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <iostream>

using namespace std::chrono_literals;

namespace llarp
{
    using rc_time = std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds>;

    rc_time time_point_now();

    /// get time right now as milliseconds, this is monotonic
    Duration_t time_now_ms();

    /// get the uptime of the process
    Duration_t uptime();

    /// convert to milliseconds
    uint64_t ToMS(Duration_t duration);

    nlohmann::json to_json(const Duration_t& t);

    // Returns a string such as "27m13s ago" or "in 1h12m" or "now".  You get precision of minutes
    // (for >=1h), seconds (>=10s), or milliseconds.  The `now_threshold` argument controls how
    // close to current time (default 1s) the time has to be to get the "now" argument.
    std::string short_time_from_now(const TimePoint_t& t, const Duration_t& now_threshold = 1s);

    // Makes a duration human readable.  This always has full millisecond precision, but formats up
    // to hours. E.g. "-4h04m12.123s" or "1234h00m09.876s.
    std::string to_string(Duration_t t);

}  // namespace llarp

// Duration_t is currently just a typedef to std::chrono::milliseconds, and specializing
// that seems wrong; leaving this here to remind us not to add it back in again.
// namespace fmt
//{
//  template <>
//  struct formatter<llarp::Duration_t>
//  {
//  };
//}  // namespace fmt
