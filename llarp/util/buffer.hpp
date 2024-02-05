#pragma once

#include "common.hpp"
#include "mem.h"
#include "types.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace llarp
{
    using byte_view_t = std::basic_string_view<uint8_t>;
    using ustring = std::basic_string<uint8_t>;
    using ustring_view = std::basic_string_view<uint8_t>;
    using bstring = std::basic_string<std::byte>;
    using bstring_view = std::basic_string_view<std::byte>;

    inline ustring operator""_us(const char* str, size_t len) noexcept
    {
        return {reinterpret_cast<const unsigned char*>(str), len};
    }

    // Helper function to switch between string_view and ustring_view
    inline ustring_view to_usv(std::string_view v)
    {
        return {reinterpret_cast<const uint8_t*>(v.data()), v.size()};
    }

    struct llarp_buffer
    {
       private:
        std::string _buf;
        std::string_view _bview;
        size_t _size;

       public:
        llarp_buffer() = default;
        llarp_buffer(size_t s) : _size{s}
        {
            _buf.reserve(_size);
            _bview = {_buf};
        }
        llarp_buffer(std::string& b) : _buf{std::move(b)}, _bview{_buf}, _size{_buf.size()}
        {}
        llarp_buffer(std::string_view bv) : _buf{bv}, _bview{_buf}, _size{_buf.size()}
        {}

        template <
            typename CharT,
            std::enable_if_t<std::is_convertible_v<CharT, char> || std::is_constructible_v<std::string, CharT>, int> =
                0>
        llarp_buffer(CharT* c) : _buf{c}, _bview{_buf}, _size{_buf.size()}
        {}

        std::string_view view() const
        {
            return _bview;
        }

        size_t size() const
        {
            return _size;
        }

        bool is_empty() const
        {
            return _buf.empty();
        }

        char* data()
        {
            return _buf.data();
        }
        char* data_at(size_t pos)
        {
            return _buf.data() + pos;
        }

        const char* vdata()
        {
            return _bview.data();
        }
        const char* vdata_at(size_t pos)
        {
            return _bview.data() + pos;
        }

        char operator[](size_t pos)
        {
            return *(data() + pos);
        }
    };

}  // namespace llarp

struct ManagedBuffer;

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

    uint8_t operator[](size_t x)
    {
        return *(this->base + x);
    }

    llarp_buffer_t() = default;

    llarp_buffer_t(uint8_t* b, uint8_t* c, size_t s) : base(b), cur(c), sz(s)
    {}

    llarp_buffer_t(const ManagedBuffer&) = delete;
    llarp_buffer_t(ManagedBuffer&&) = delete;

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

    std::string to_string() const
    {
        return {reinterpret_cast<const char*>(base), sz};
    }

    uint8_t* begin()
    {
        return base;
    }
    const uint8_t* begin() const
    {
        return base;
    }
    uint8_t* end()
    {
        return base + sz;
    }
    const uint8_t* end() const
    {
        return base + sz;
    }

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
    llarp::byte_view_t view_all() const
    {
        return {base, sz};
    }

    /// get a read-only view over the remaining/unused region
    llarp::byte_view_t view_remaining() const
    {
        return {cur, size_left()};
    }

    /// Part of the curse.  Returns true if the remaining buffer space starts with the given string
    /// view.
    bool startswith(std::string_view prefix_str) const
    {
        llarp::byte_view_t prefix{reinterpret_cast<const uint8_t*>(prefix_str.data()), prefix_str.size()};
        return view_remaining().substr(0, prefix.size()) == prefix;
    }

   private:
    friend struct ManagedBuffer;
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

/**
 Provide a copyable/moveable wrapper around `llarp_buffer_t`.
 */
struct ManagedBuffer
{
    llarp_buffer_t underlying;

    ManagedBuffer() = delete;

    explicit ManagedBuffer(const llarp_buffer_t& b) : underlying(b)
    {}

    ManagedBuffer(ManagedBuffer&&) = default;
    ManagedBuffer(const ManagedBuffer&) = default;

    operator const llarp_buffer_t&() const
    {
        return underlying;
    }
};

namespace llarp
{
    // Wrapper around a std::unique_ptr<uint8_t[]> that owns its own memory and is also implicitly
    // convertible to a llarp_buffer_t.
    struct OwnedBuffer
    {
        std::unique_ptr<uint8_t[]> buf;
        size_t sz;

        template <typename T, typename = std::enable_if_t<sizeof(T) == 1>>
        OwnedBuffer(std::unique_ptr<T[]> buf, size_t sz) : buf{reinterpret_cast<uint8_t*>(buf.release())}, sz{sz}
        {}

        // Create a new, uninitialized owned buffer of the given size.
        explicit OwnedBuffer(size_t sz) : OwnedBuffer{std::make_unique<uint8_t[]>(sz), sz}
        {}

        // copy content from existing memory
        explicit OwnedBuffer(const uint8_t* ptr, size_t sz) : OwnedBuffer{sz}
        {
            std::copy_n(ptr, sz, buf.get());
        }

        OwnedBuffer(const OwnedBuffer&) = delete;
        OwnedBuffer& operator=(const OwnedBuffer&) = delete;
        OwnedBuffer(OwnedBuffer&&) = default;
        OwnedBuffer& operator=(OwnedBuffer&&) = delete;

        // Implicit conversion so that this OwnedBuffer can be passed to anything taking a
        // llarp_buffer_t
        operator llarp_buffer_t()
        {
            return {buf.get(), sz};
        }

        // Creates an owned buffer by copying from a llarp_buffer_t.  (Can also be used to copy from
        // another OwnedBuffer via the implicit conversion operator above).
        static OwnedBuffer copy_from(const llarp_buffer_t& b);

        // Creates an owned buffer by copying the used portion of a llarp_buffer_t (i.e. from base
        // to cur), for when a llarp_buffer_t is used in write mode.
        static OwnedBuffer copy_used(const llarp_buffer_t& b);

        /// copy everything in this owned buffer into a vector
        std::vector<uint8_t> copy() const;
    };

}  // namespace llarp
