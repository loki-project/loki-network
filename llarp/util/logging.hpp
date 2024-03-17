#pragma once

// Header for making actual log statements such as llarp::log::Info and so on work.

#include <oxen/log.hpp>
#include <oxen/log/ring_buffer_sink.hpp>

#include <array>
#include <string>
#include <string_view>

namespace llarp
{
    namespace log = oxen::log;

    inline std::shared_ptr<log::RingBufferSink> logRingBuffer = nullptr;
}  // namespace llarp
