#pragma once

#include <llarp/util/buffer.hpp>
#include <llarp/util/formattable.hpp>

#include <cstddef>
#include <iosfwd>
#include <string_view>
#include <type_traits>

namespace llarp
{
    // Buffer printer lets you print a string as a nicely formatted buffer with a hex breakdown and
    // visual representation of the data for logging purposes.  Wraps the string data with a object
    // that prints the buffer format during output; use as:
    //
    //   fmt::print("{}", buffer_printer(my_buffer));
    //
    // or similarly in a log statement.
    //
    struct buffer_printer : public oxen::quic::buffer_printer
    {
        std::basic_string_view<std::byte> buf;

        using oxen::quic::buffer_printer::buffer_printer;

        // llarp_buffer_t printer:
        explicit buffer_printer(const llarp_buffer_t& buf)
            : buffer_printer(std::basic_string_view<uint8_t>{buf.base, buf.sz})
        {}

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

}  // namespace llarp
