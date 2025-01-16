#pragma once

#include "common.hpp"

#include <limits>

extern "C"
{
    extern void randombytes(unsigned char* const ptr, unsigned long long sz);
}

namespace llarp
{
    struct CSRNG
    {
        using result_type = uint64_t;

        static constexpr uint64_t min() { return std::numeric_limits<uint64_t>::min(); }

        static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); }

        uint64_t randint()
        {
            uint64_t i;
            randombytes((uint8_t*)&i, sizeof(i));
            return i;
        }

        uint64_t operator()() { return randint(); }
    };

    extern CSRNG csrng;
}  // namespace llarp
