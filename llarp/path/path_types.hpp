#pragma once

#include <llarp/constants/path.hpp>
#include <llarp/contact/relay_contact.hpp>
#include <llarp/crypto/constants.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/util/aligned.hpp>

namespace llarp
{
    struct HopID final : public AlignedBuffer<PATHIDSIZE>
    {
        using AlignedBuffer<PATHIDSIZE>::AlignedBuffer;

        static HopID make_random()
        {
            HopID h;
            h.Randomize();
            return h;
        }
    };
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::HopID> : hash<llarp::AlignedBuffer<llarp::HopID::SIZE>>
    {};
}  // namespace std
