#pragma once
#include <oxenc/endian.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>

namespace llarp
{
    /// 128-bit unsigned integer.  Does *not* support
    /// multiplication/division/modulus.
    struct uint128_t
    {
        // Swap order on little/big endian so that the first byte of the struct is
        // always most significant on big endian and least significant on little
        // endian.
#ifdef __BIG_ENDIAN__
        uint64_t upper, lower;
#else
        uint64_t lower, upper;
#endif

        // Initializes with 0s
        constexpr uint128_t() : uint128_t{0, 0} {}

        // Initializes with least-significant value
        constexpr uint128_t(uint64_t lower) : uint128_t{0, lower} {}

        // Initializes with upper and lower values
        constexpr uint128_t(uint64_t upper, uint64_t lower)
        // clang-format off
#ifdef __BIG_ENDIAN__
        : upper{upper}, lower{lower}
#else
        : lower{lower}, upper{upper}
#endif
        // clang-format on
        {}

        constexpr uint128_t(const uint128_t&) = default;
        constexpr uint128_t(uint128_t&&) = default;
        constexpr uint128_t& operator=(const uint128_t&) = default;
        constexpr uint128_t& operator=(uint128_t&&) = default;

        // bitwise and
        constexpr uint128_t& operator&=(const uint128_t& o)
        {
            upper &= o.upper;
            lower &= o.lower;
            return *this;
        }
        constexpr uint128_t operator&(const uint128_t& o) const
        {
            uint128_t result = *this;
            result &= o;
            return result;
        }

        // bitwise or
        constexpr uint128_t& operator|=(const uint128_t& o)
        {
            upper |= o.upper;
            lower |= o.lower;
            return *this;
        }
        constexpr uint128_t operator|(const uint128_t& o) const
        {
            uint128_t result = *this;
            result |= o;
            return result;
        }

        // bitwise xor
        constexpr uint128_t& operator^=(const uint128_t& o)
        {
            upper ^= o.upper;
            lower ^= o.lower;
            return *this;
        }
        constexpr uint128_t operator^(const uint128_t& o) const
        {
            uint128_t result = *this;
            result ^= o;
            return result;
        }

        // bitwise not
        constexpr uint128_t operator~() const { return {~upper, ~lower}; }

        // bool: true if any bit set
        explicit constexpr operator bool() const { return static_cast<bool>(lower) || static_cast<bool>(upper); }

        // Casting to basic unsigned int types: casts away upper bits
        explicit constexpr operator uint8_t() const { return static_cast<uint8_t>(lower); }
        explicit constexpr operator uint16_t() const { return static_cast<uint16_t>(lower); }
        explicit constexpr operator uint32_t() const { return static_cast<uint32_t>(lower); }
        explicit constexpr operator uint64_t() const { return lower; }

        constexpr bool operator==(const uint128_t& b) const { return lower == b.lower && upper == b.upper; }

        constexpr bool operator!=(const uint128_t& b) const { return lower != b.lower || upper != b.upper; }

        constexpr bool operator<(const uint128_t& b) const
        {
            return std::tie(upper, lower) < std::tie(b.upper, b.lower);
        }

        constexpr bool operator<=(const uint128_t& b) const
        {
            return std::tie(upper, lower) <= std::tie(b.upper, b.lower);
        }

        constexpr bool operator>(const uint128_t& b) const
        {
            return std::tie(upper, lower) > std::tie(b.upper, b.lower);
        }

        constexpr bool operator>=(const uint128_t& b) const
        {
            return std::tie(upper, lower) >= std::tie(b.upper, b.lower);
        }

        constexpr uint128_t& operator++()
        {
            if (++lower == 0)
                ++upper;
            return *this;
        }

        constexpr uint128_t operator++(int)
        {
            auto copy = *this;
            ++*this;
            return copy;
        }

        constexpr uint128_t& operator+=(const uint128_t& b)
        {
            lower += b.lower;
            if (lower < b.lower)
                ++upper;
            upper += b.upper;
            return *this;
        }
        constexpr uint128_t operator+(const uint128_t& b) const
        {
            uint128_t result = *this;
            result += b;
            return result;
        }

        constexpr uint128_t& operator-=(const uint128_t& b)
        {
            if (b.lower > lower)
                --upper;
            lower -= b.lower;
            upper -= b.upper;
            return *this;
        }
        constexpr uint128_t operator-(const uint128_t& b) const
        {
            uint128_t result = *this;
            result -= b;
            return result;
        }

        constexpr uint128_t& operator<<=(uint64_t shift)
        {
            if (shift == 0)
            {
            }
            else if (shift < 64)
            {
                upper = upper << shift | (lower >> (64 - shift));
                lower <<= shift;
            }
            else if (shift == 64)
            {
                upper = lower;
                lower = 0;
            }
            else if (shift < 128)
            {
                upper = lower << (shift - 64);
                lower = 0;
            }
            else
            {
                upper = lower = 0;
            }
            return *this;
        }
        constexpr uint128_t operator<<(uint64_t shift) const
        {
            uint128_t result = *this;
            result <<= shift;
            return result;
        }

        constexpr uint128_t& operator>>=(uint64_t shift)
        {
            if (shift == 0)
            {
            }
            else if (shift < 64)
            {
                lower = lower >> shift | upper << (64 - shift);
                upper >>= shift;
            }
            else if (shift == 64)
            {
                lower = upper;
                upper = 0;
            }
            else if (shift < 128)
            {
                lower = upper >> (shift - 64);
                upper = 0;
            }
            else
            {
                upper = lower = 0;
            }
            return *this;
        }

        constexpr uint128_t operator>>(uint64_t shift) const
        {
            uint128_t result = *this;
            result >>= shift;
            return result;
        }
    };

    static_assert(sizeof(uint128_t) == 16, "uint128_t has unexpected size (padding?)");

}  // namespace llarp

namespace std
{
    // Hash function for uint128_t
    template <>
    struct hash<llarp::uint128_t>
    {
        size_t operator()(const llarp::uint128_t& i) const
        {
            size_t h = std::hash<uint64_t>()(i.lower);
            h ^= std::hash<uint64_t>()(i.upper) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
}  // namespace std

inline llarp::uint128_t ntoh128(llarp::uint128_t i)
{
#ifdef __BIG_ENDIAN__
    return i;
#else
    const auto loSwapped = oxenc::big_to_host(i.lower);
    const auto hiSwapped = oxenc::big_to_host(i.upper);
    return {/*upper=*/loSwapped, /*lower=*/hiSwapped};
#endif
}

inline llarp::uint128_t hton128(llarp::uint128_t i)
{
    return ntoh128(i);  // Same bit flipping as n-to-h
}
