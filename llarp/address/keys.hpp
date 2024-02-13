#pragma once

#include <llarp/crypto/constants.hpp>
#include <llarp/util/aligned.hpp>

/** TODO:
    - re-configure string_view and ustring_view methods after deprecating RouterID

*/

namespace llarp
{
    struct PublicKey : public AlignedBuffer<PUBKEYSIZE>
    {
        PublicKey() = default;

        std::string to_string() const;

        explicit PublicKey(const uint8_t* data) : AlignedBuffer<PUBKEYSIZE>{data}
        {}
        explicit PublicKey(const std::array<uint8_t, PUBKEYSIZE>& data) : AlignedBuffer<PUBKEYSIZE>{data}
        {}
        explicit PublicKey(ustring_view data) : AlignedBuffer<PUBKEYSIZE>{data.data()}
        {}
        explicit PublicKey(std::string_view data) : PublicKey{to_usv(data)}
        {}
        PublicKey(const PublicKey& other) : PublicKey{other.data()}
        {}
        PublicKey(PublicKey&& other) : PublicKey{other.data()}
        {}

        PublicKey& operator=(const PublicKey& other);

        bool operator<(const PublicKey& other) const;
        bool operator==(const PublicKey& other) const;
        bool operator!=(const PublicKey& other) const;
    };

    struct RelayPubKey final : public PublicKey
    {
        RelayPubKey() = delete;

        explicit RelayPubKey(const uint8_t* data) : PublicKey{data}
        {}
        explicit RelayPubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : PublicKey{data}
        {}
        explicit RelayPubKey(ustring_view data) : PublicKey{data.data()}
        {}
        explicit RelayPubKey(std::string_view data) : RelayPubKey{to_usv(data)}
        {}
        explicit RelayPubKey(const RelayPubKey& other) : RelayPubKey{other.data()}
        {}

        std::string to_string() const;

        RelayPubKey& operator=(const RelayPubKey& other);

        bool operator<(const RelayPubKey& other) const;
        bool operator==(const RelayPubKey& other) const;
        bool operator!=(const RelayPubKey& other) const;
    };

    struct ClientPubKey final : public PublicKey
    {
        ClientPubKey() = delete;

        explicit ClientPubKey(const uint8_t* data) : PublicKey{data}
        {}
        explicit ClientPubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : PublicKey{data}
        {}
        explicit ClientPubKey(ustring_view data) : PublicKey{data.data()}
        {}
        explicit ClientPubKey(std::string_view data) : ClientPubKey{to_usv(data)}
        {}
        explicit ClientPubKey(const ClientPubKey& other) : ClientPubKey{other.data()}
        {}

        std::string to_string() const;

        ClientPubKey& operator=(const ClientPubKey& other);

        bool operator<(const ClientPubKey& other) const;
        bool operator==(const ClientPubKey& other) const;
        bool operator!=(const ClientPubKey& other) const;
    };

    template <>
    inline constexpr bool IsToStringFormattable<PublicKey> = true;

    template <typename pk_t>
    inline constexpr bool IsToStringFormattable<pk_t, std::enable_if_t<std::is_base_of_v<PublicKey, pk_t>>> = true;

}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::PublicKey> : public hash<llarp::AlignedBuffer<PUBKEYSIZE>>
    {};

    template <>
    struct hash<llarp::ClientPubKey> : public hash<llarp::PublicKey>
    {};

    template <>
    struct hash<llarp::RelayPubKey> : public hash<llarp::PublicKey>
    {};
}  //  namespace std
