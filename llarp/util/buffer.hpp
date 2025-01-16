#pragma once

#include "common.hpp"
#include "mem.h"

#include <oxenc/span.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace llarp
{
    using cspan = oxenc::const_span<const char>;
    using uspan = oxenc::const_span<const unsigned char>;
    using span = oxenc::const_span<const std::byte>;

    using ustring = std::basic_string<uint8_t>;
    using ustring_view = std::basic_string_view<uint8_t>;
    using bstring = std::basic_string<std::byte>;
    using bstring_view = std::basic_string_view<std::byte>;

    inline ustring operator""_us(const char* str, size_t len) noexcept
    {
        return {reinterpret_cast<const unsigned char*>(str), len};
    }

    // Helper function to switch between string_view and ustring_view
    inline ustring_view to_usv(std::string_view v) { return {reinterpret_cast<const uint8_t*>(v.data()), v.size()}; }

    template <oxenc::basic_char T>
    inline std::span<uint8_t> to_uspan(std::basic_string<T>& v)
    {
        return std::span<uint8_t>{reinterpret_cast<uint8_t*>(v.data()), v.size()};
    }
}  // namespace llarp

/// TODO: replace usage of these with std::span (via a backport until we move to C++20).  That's a
/// fairly big job, though, as llarp_buffer_t is currently used a bit differently (i.e. maintains
/// both start and current position, plus has some value reading/writing methods).
struct /* [[deprecated("this type is stupid, use something else")]] */ llarp_buffer_t
{
    /// starting memory address
    uint8_t* base{nullptr};
    /// memory address of stream position
    uint8_t* cur{nullptr};
    /// max size of buffer
    size_t sz{0};

    uint8_t operator[](size_t x) { return *(this->base + x); }

    llarp_buffer_t() = default;

    llarp_buffer_t(uint8_t* b, uint8_t* c, size_t s) : base(b), cur(c), sz(s) {}

    template <typename Byte>
    static constexpr bool is_basic_byte = sizeof(Byte) == 1 and std::is_trivially_copyable_v<Byte>;

    /// Construct referencing some 1-byte, trivially copyable (e.g. char, unsigned char, uint8_t)
    /// pointer type and a buffer size.
    template <typename Byte, typename = std::enable_if_t<not std::is_const_v<Byte> && is_basic_byte<Byte>>>
    llarp_buffer_t(Byte* buf, size_t sz) : base{reinterpret_cast<uint8_t*>(buf)}, cur{base}, sz{sz}
    {}

    /// initialize llarp_buffer_t from vector or array of byte-like values
    template <typename Byte, typename = std::enable_if_t<not std::is_const_v<Byte> && is_basic_byte<Byte>>>
    llarp_buffer_t(std::vector<Byte>& b) : llarp_buffer_t{b.data(), b.size()}
    {}

    template <typename Byte, size_t N, typename = std::enable_if_t<not std::is_const_v<Byte> && is_basic_byte<Byte>>>
    llarp_buffer_t(std::array<Byte, N>& b) : llarp_buffer_t{b.data(), b.size()}
    {}

    // These overloads, const_casting away the const, are not just gross but downright dangerous:
    template <typename Byte, typename = std::enable_if_t<is_basic_byte<Byte>>>
    llarp_buffer_t(const Byte* buf, size_t sz) : llarp_buffer_t{const_cast<Byte*>(buf), sz}
    {}

    template <typename Byte, typename = std::enable_if_t<is_basic_byte<Byte>>>
    llarp_buffer_t(const std::vector<Byte>& b) : llarp_buffer_t{const_cast<Byte*>(b.data()), b.size()}
    {}

    template <typename Byte, size_t N, typename = std::enable_if_t<is_basic_byte<Byte>>>
    llarp_buffer_t(const std::array<Byte, N>& b) : llarp_buffer_t{const_cast<Byte*>(b.data()), b.size()}
    {}

    /// Explicitly construct a llarp_buffer_t from anything with a `.data()` and a `.size()`.
    /// Cursed.
    template <typename T, typename = std::void_t<decltype(std::declval<T>().data() + std::declval<T>().size())>>
    explicit llarp_buffer_t(T&& t) : llarp_buffer_t{t.data(), t.size()}
    {}

    std::string to_string() const { return {reinterpret_cast<const char*>(base), sz}; }

    uint8_t* begin() { return base; }
    const uint8_t* begin() const { return base; }
    uint8_t* end() { return base + sz; }
    const uint8_t* end() const { return base + sz; }

    size_t size_left() const
    {
        size_t diff = cur - base;
        assert(diff <= sz);
        if (diff > sz)
            return 0;
        return sz - diff;
    }

    template <typename OutputIt>
    bool read_into(OutputIt begin, OutputIt end);

    template <typename InputIt>
    bool write(InputIt begin, InputIt end);

#ifndef _WIN32
    bool writef(const char* fmt, ...) __attribute__((format(printf, 2, 3)));

#elif defined(__MINGW64__) || defined(__MINGW32__)
    bool writef(const char* fmt, ...) __attribute__((__format__(__MINGW_PRINTF_FORMAT, 2, 3)));
#else
    bool writef(const char* fmt, ...);
#endif

    bool put_uint16(uint16_t i);
    bool put_uint32(uint32_t i);

    bool put_uint64(uint64_t i);

    bool read_uint16(uint16_t& i);
    bool read_uint32(uint32_t& i);

    bool read_uint64(uint64_t& i);

    size_t read_until(char delim, uint8_t* result, size_t resultlen);

    /// make a copy of this buffer
    std::vector<uint8_t> copy() const;

    /// get a read-only view over the entire region
    llarp::ustring_view view_all() const { return {base, sz}; }

    /// get a read-only view over the remaining/unused region
    llarp::ustring_view view_remaining() const { return {cur, size_left()}; }

    /// Part of the curse.  Returns true if the remaining buffer space starts with the given string
    /// view.
    bool startswith(std::string_view prefix_str) const
    {
        llarp::ustring_view prefix{reinterpret_cast<const uint8_t*>(prefix_str.data()), prefix_str.size()};
        return view_remaining().substr(0, prefix.size()) == prefix;
    }

  private:
    llarp_buffer_t(const llarp_buffer_t&) = default;
    llarp_buffer_t(llarp_buffer_t&&) = default;
};

template <typename OutputIt>
bool llarp_buffer_t::read_into(OutputIt begin, OutputIt end)
{
    auto dist = std::distance(begin, end);
    if (static_cast<decltype(dist)>(size_left()) >= dist)
    {
        std::copy_n(cur, dist, begin);
        cur += dist;
        return true;
    }
    return false;
}

template <typename InputIt>
bool llarp_buffer_t::write(InputIt begin, InputIt end)
{
    auto dist = std::distance(begin, end);
    if (static_cast<decltype(dist)>(size_left()) >= dist)
    {
        cur = std::copy(begin, end, cur);
        return true;
    }
    return false;
}
