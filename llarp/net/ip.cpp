#include "ip.hpp"

#include <cstring>

namespace llarp::net
{
    huint128_t In6ToHUInt(in6_addr addr)
    {
        uint8_t* ptr = reinterpret_cast<uint8_t*>(addr.s6_addr);
        uint128_t x{0};
        for (int i = 0; i < 16; i++)
        {
            x <<= 8;
            x |= ptr[i];
        }
        return huint128_t{x};
    }

    in6_addr HUIntToIn6(huint128_t x)
    {
        in6_addr addr;
        auto i = ntoh128(x.h);
        std::memcpy(&addr, &i, 16);
        return addr;
    }

}  // namespace llarp::net
