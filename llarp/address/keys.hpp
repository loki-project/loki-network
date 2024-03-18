#pragma once

#include <llarp/crypto/constants.hpp>
#include <llarp/util/aligned.hpp>

/** TODO:
    - re-configure string_view and ustring_view methods after deprecating RouterID

*/

namespace llarp
{
    struct PubKey : public AlignedBuffer<PUBKEYSIZE>
    {
        PubKey() = default;

        bool from_hex(const std::string& str);

        std::string to_string() const;

        explicit PubKey(const uint8_t* data) : AlignedBuffer<PUBKEYSIZE>{data}
        {}
        explicit PubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : AlignedBuffer<PUBKEYSIZE>{data}
        {}
        explicit PubKey(ustring_view data) : AlignedBuffer<PUBKEYSIZE>{data.data()}
        {}
        explicit PubKey(std::string_view data) : PubKey{to_usv(data)}
        {}
        PubKey(const PubKey& other) : PubKey{other.data()}
        {}
        PubKey(PubKey&& other) : PubKey{other.data()}
        {}

        PubKey& operator=(const PubKey& other);

        // revisit this
        PubKey& operator=(const uint8_t* ptr);

        bool operator<(const PubKey& other) const;
        bool operator==(const PubKey& other) const;
        bool operator!=(const PubKey& other) const;
    };

    struct RelayPubKey final : public PubKey
    {
        RelayPubKey() = default;

        explicit RelayPubKey(const uint8_t* data) : PubKey{data}
        {}
        explicit RelayPubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : PubKey{data}
        {}
        explicit RelayPubKey(ustring_view data) : PubKey{data.data()}
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

    struct ClientPubKey final : public PubKey
    {
        ClientPubKey() = default;

        explicit ClientPubKey(const uint8_t* data) : PubKey{data}
        {}
        explicit ClientPubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : PubKey{data}
        {}
        explicit ClientPubKey(ustring_view data) : PubKey{data.data()}
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
    inline constexpr bool IsToStringFormattable<PubKey> = true;

    template <typename pk_t>
    inline constexpr bool IsToStringFormattable<pk_t, std::enable_if_t<std::is_base_of_v<PubKey, pk_t>>> = true;

    template <typename PK_t, std::enable_if_t<std::is_base_of_v<PubKey, PK_t>, int> = 0>
    PK_t make_from_hex(const std::string& str)
    {
        PK_t p;
        oxenc::from_hex(str.begin(), str.end(), p.begin());
        return p;
    }

}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::PubKey> : public hash<llarp::AlignedBuffer<PUBKEYSIZE>>
    {};

    template <>
    struct hash<llarp::ClientPubKey> : public hash<llarp::PubKey>
    {};

    template <>
    struct hash<llarp::RelayPubKey> : public hash<llarp::PubKey>
    {};
}  //  namespace std
