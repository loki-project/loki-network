#pragma once

#include "bencode.h"

#include <llarp/util/formattable.hpp>
#include <llarp/util/logging.hpp>

#include <oxenc/hex.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <type_traits>

extern "C"
{
    extern void randombytes(unsigned char* const ptr, unsigned long long sz);

    extern int sodium_is_zero(const unsigned char* n, const size_t nlen);
}
namespace llarp
{
    /// aligned buffer that is sz bytes long and aligns to the nearest Alignment
    template <size_t sz>
    // Microsoft C malloc(3C) cannot return pointers aligned wider than 8 ffs
#ifdef _WIN32
    struct alignas(uint64_t) AlignedBuffer
#else
    struct alignas(std::max_align_t) AlignedBuffer
#endif
    {
        static_assert(alignof(std::max_align_t) <= 16, "insane alignment");
        static_assert(
            sz >= 8,
            "AlignedBuffer cannot be used with buffers smaller than 8 "
            "bytes");

        static constexpr size_t SIZE = sz;

        virtual ~AlignedBuffer() = default;

        AlignedBuffer()
        {
            Zero();
        }

        explicit AlignedBuffer(const uint8_t* data)
        {
            *this = data;
        }

        explicit AlignedBuffer(const std::array<uint8_t, SIZE>& buf)
        {
            _data = buf;
        }

        AlignedBuffer& operator=(const uint8_t* data)
        {
            std::memcpy(_data.data(), data, sz);
            return *this;
        }

        /// bitwise NOT
        AlignedBuffer<sz> operator~() const
        {
            AlignedBuffer<sz> ret;
            std::transform(begin(), end(), ret.begin(), [](uint8_t a) { return ~a; });

            return ret;
        }

        bool operator==(const AlignedBuffer& other) const
        {
            return _data == other._data;
        }

        bool operator!=(const AlignedBuffer& other) const
        {
            return _data != other._data;
        }

        bool operator<(const AlignedBuffer& other) const
        {
            return _data < other._data;
        }

        bool operator>(const AlignedBuffer& other) const
        {
            return _data > other._data;
        }

        bool operator<=(const AlignedBuffer& other) const
        {
            return _data <= other._data;
        }

        bool operator>=(const AlignedBuffer& other) const
        {
            return _data >= other._data;
        }

        AlignedBuffer operator^(const AlignedBuffer& other) const
        {
            AlignedBuffer<sz> ret;
            std::transform(begin(), end(), other.begin(), ret.begin(), std::bit_xor<>());
            return ret;
        }

        AlignedBuffer& operator^=(const AlignedBuffer& other)
        {
            // Mutate in place instead.
            for (size_t i = 0; i < sz; ++i)
            {
                _data[i] ^= other._data[i];
            }
            return *this;
        }

        uint8_t& operator[](size_t idx)
        {
            assert(idx < SIZE);
            return _data[idx];
        }

        const uint8_t& operator[](size_t idx) const
        {
            assert(idx < SIZE);
            return _data[idx];
        }

        static constexpr size_t size()
        {
            return sz;
        }

        void Fill(uint8_t f)
        {
            _data.fill(f);
        }

        std::array<uint8_t, SIZE>& as_array()
        {
            return _data;
        }

        const std::array<uint8_t, SIZE>& as_array() const
        {
            return _data;
        }

        uint8_t* data()
        {
            return _data.data();
        }

        const uint8_t* data() const
        {
            return _data.data();
        }

        bool IsZero() const
        {
            const uint64_t* ptr = reinterpret_cast<const uint64_t*>(data());
            for (size_t idx = 0; idx < SIZE / sizeof(uint64_t); idx++)
            {
                if (ptr[idx])
                    return false;
            }
            return true;
        }

        void Zero()
        {
            _data.fill(0);
        }

        virtual void Randomize()
        {
            randombytes(data(), SIZE);
        }

        typename std::array<uint8_t, SIZE>::iterator begin()
        {
            return _data.begin();
        }

        typename std::array<uint8_t, SIZE>::iterator end()
        {
            return _data.end();
        }

        typename std::array<uint8_t, SIZE>::const_iterator begin() const
        {
            return _data.cbegin();
        }

        typename std::array<uint8_t, SIZE>::const_iterator end() const
        {
            return _data.cend();
        }

        bool FromBytestring(llarp_buffer_t* buf)
        {
            if (buf->sz != sz)
            {
                llarp::LogError("bdecode buffer size mismatch ", buf->sz, "!=", sz);
                return false;
            }
            memcpy(data(), buf->base, sz);
            return true;
        }

        bool from_string(std::string_view b)
        {
            if (b.size() != sz)
            {
                log::error(util_cat, "Error: buffer size mismatch in aligned buffer!");
                return false;
            }

            std::memcpy(_data.data(), b.data(), b.size());
            return true;
        }

        bool bt_encode(llarp_buffer_t* buf) const
        {
            return bencode_write_bytestring(buf, data(), sz);
        }

        std::string bt_encode() const
        {
            return {reinterpret_cast<const char*>(data()), sz};
        }

        bool BDecode(llarp_buffer_t* buf)
        {
            llarp_buffer_t strbuf;
            if (!bencode_read_string(buf, &strbuf))
            {
                return false;
            }
            return FromBytestring(&strbuf);
        }

        std::string_view ToView() const
        {
            return {reinterpret_cast<const char*>(data()), sz};
        }

        std::string ToHex() const
        {
            return oxenc::to_hex(begin(), end());
        }

        std::string ShortHex() const
        {
            return oxenc::to_hex(begin(), begin() + 4);
        }

        bool FromHex(std::string_view str)
        {
            if (str.size() != 2 * size() || !oxenc::is_hex(str))
                return false;
            oxenc::from_hex(str.begin(), str.end(), begin());
            return true;
        }

       private:
        std::array<uint8_t, SIZE> _data;
    };

    namespace detail
    {
        template <size_t Sz>
        static std::true_type is_aligned_buffer_impl(AlignedBuffer<Sz>*);

        static std::false_type is_aligned_buffer_impl(...);
    }  // namespace detail
    // True if T is or is derived from AlignedBuffer<N> for any N
    template <typename T>
    constexpr inline bool is_aligned_buffer = decltype(detail::is_aligned_buffer_impl(static_cast<T*>(nullptr)))::value;

}  // namespace llarp

namespace fmt
{
    // Any AlignedBuffer<N> (or subclass) gets hex formatted when output:
    template <typename T>
    struct formatter<T, char, std::enable_if_t<llarp::is_aligned_buffer<T> && !llarp::IsToStringFormattable<T>>>
        : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx)
        {
            auto it = oxenc::hex_encoder{val.begin(), val.end()};
            return std::copy(it, it.end(), ctx.out());
        }
    };
}  // namespace fmt

namespace std
{
    template <size_t sz>
    struct hash<llarp::AlignedBuffer<sz>>
    {
        std::size_t operator()(const llarp::AlignedBuffer<sz>& buf) const noexcept
        {
            std::size_t h = 0;
            std::memcpy(&h, buf.data(), sizeof(std::size_t));
            return h;
        }
    };
}  // namespace std
