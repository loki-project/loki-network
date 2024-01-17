#pragma once

#include "util/aligned.hpp"
#include "util/types.hpp"

#include <llarp/crypto/types.hpp>

namespace llarp
{
    struct RouterID : public PubKey
    {
        static constexpr size_t SIZE = 32;

        using Data = std::array<byte_t, SIZE>;

        RouterID() = default;

        RouterID(const byte_t* buf) : PubKey(buf)
        {}

        RouterID(const Data& data) : PubKey(data)
        {}

        RouterID(ustring_view data) : PubKey(data.data())
        {}

        RouterID(std::string_view data) : RouterID(to_usv(data))
        {}

        StatusObject ExtractStatus() const;

        std::string ToString() const;

        std::string ShortString() const;

        // FIXME: this is deceptively named: it parses something base32z formatted with .snode on
        // the end, so should probably be called "from_snode_address" or "from_base32z" or something
        // that doesn't sound exactly like the other (different) from_strings of its base classes.
        bool from_snode_address(std::string_view str);

        RouterID& operator=(const byte_t* ptr)
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
    constexpr inline bool IsToStringFormattable<RouterID> = true;
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::RouterID> : hash<llarp::AlignedBuffer<llarp::RouterID::SIZE>>
    {};
}  // namespace std
