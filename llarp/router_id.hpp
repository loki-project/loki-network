#pragma once

#include "util/aligned.hpp"
#include "util/types.hpp"

#include <llarp/crypto/types.hpp>

namespace llarp
{
    struct RouterID : public PubKey
    {
        static constexpr size_t SIZE = 32;

        using Data = std::array<uint8_t, SIZE>;

        RouterID() = default;

        RouterID(const uint8_t* buf) : PubKey(buf)
        {}

        RouterID(const Data& data) : PubKey(data)
        {}

        RouterID(ustring_view data) : PubKey(data.data())
        {}

        RouterID(std::string_view data) : RouterID(to_usv(data))
        {}

        StatusObject ExtractStatus() const;

        std::string to_string() const;

        std::string ShortString() const;

        bool from_snode_address(std::string_view str);

        RouterID& operator=(const uint8_t* ptr)
        {
            std::copy(ptr, ptr + SIZE, begin());
            return *this;
        }
    };

    inline bool operator==(const RouterID& lhs, const RouterID& rhs)
    {
        return lhs.as_array() == rhs.as_array();
    }

    template <>
    inline constexpr bool IsToStringFormattable<RouterID> = true;
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::RouterID> : hash<llarp::AlignedBuffer<llarp::RouterID::SIZE>>
    {};
}  // namespace std
