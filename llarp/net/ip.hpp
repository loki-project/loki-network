#pragma once

#include "net_int.hpp"

#include <cstdint>

namespace llarp::net
{
    huint128_t In6ToHUInt(in6_addr addr);

    in6_addr HUIntToIn6(huint128_t x);

    constexpr huint128_t ExpandV4(huint32_t x)
    {
        return huint128_t{0x0000'ffff'0000'0000UL} | huint128_t{x.h};
    }

    constexpr huint128_t ExpandV4Lan(huint32_t x)
    {
        return huint128_t{uint128_t{0xfd00'0000'0000'0000UL, 0UL}} | huint128_t{x.h};
    }

    constexpr huint32_t TruncateV6(huint128_t x)
    {
        huint32_t ret = {0};
        ret.h = (uint32_t)(x.h & 0x0000'0000'ffff'ffffUL);
        return ret;
    }

}  // namespace llarp::net
