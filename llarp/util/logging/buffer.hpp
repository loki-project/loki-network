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
    struct buffer_printer
    {
        std::basic_string_view<std::byte> buf;

        // Constructed from any type of string_view<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(std::basic_string_view<T> buf)
            : buf{reinterpret_cast<const std::byte*>(buf.data()), buf.size()}
        {}

        // Constructed from any type of lvalue string<T> for a single-byte T (char, std::byte,
        // uint8_t, etc.)
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(const std::basic_string<T>& buf) : buffer_printer(std::basic_string_view<T>{buf})
        {}

        // *Not* constructable from a string<T> rvalue (because we only hold a view and do not take
        // ownership).
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(std::basic_string<T>&& buf) = delete;

        // Constructable from a (T*, size) argument pair, for byte-sized T's.
        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        explicit buffer_printer(const T* data, size_t size) : buffer_printer(std::basic_string_view<T>{data, size})
        {}

        // llarp_buffer_t printer:
        explicit buffer_printer(const llarp_buffer_t& buf)
            : buffer_printer(std::basic_string_view<uint8_t>{buf.base, buf.sz})
        {}

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

}  // namespace llarp
