#pragma once

#include <llarp/crypto/types.hpp>

namespace llarp
{
    struct RelayPubKey : public PubKey
    {
        RelayPubKey() = delete;

        explicit RelayPubKey(const uint8_t* data) : PubKey{data}
        {}
        explicit RelayPubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : PubKey{data}
        {}
        explicit RelayPubKey(ustring_view data) : PubKey{data.data()}
        {}
        explicit RelayPubKey(std::string_view data) : RelayPubKey{to_usv(data)}
        {}

        // std::string to_string() const;
    };

    struct ClientPubKey : public PubKey
    {
        ClientPubKey() = delete;

        explicit ClientPubKey(const uint8_t* data) : PubKey{data}
        {}
        explicit ClientPubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : PubKey{data}
        {}
        explicit ClientPubKey(ustring_view data) : PubKey{data.data()}
        {}
        explicit ClientPubKey(std::string_view data) : ClientPubKey{to_usv(data)}
        {}
    };

    template <>
    inline constexpr bool IsToStringFormattable<RelayPubKey> = true;
    template <>
    inline constexpr bool IsToStringFormattable<ClientPubKey> = true;
}  // namespace llarp
