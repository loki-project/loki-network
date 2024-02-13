#pragma once

#include "keys.hpp"

#include <llarp/util/aligned.hpp>
#include <llarp/util/fs.hpp>
#include <llarp/util/types.hpp>

#include <oxen/quic.hpp>

#include <set>
#include <utility>

namespace llarp
{
    namespace TLD
    {
        inline constexpr auto RELAY = ".snode"sv;
        inline constexpr auto CLIENT = ".loki"sv;

        std::set<std::string_view> allowed = {RELAY, CLIENT};
    }  //  namespace TLD

    struct RemoteAddr
    {
       public:
        RemoteAddr() = default;

        explicit RemoteAddr(PublicKey pk, std::string_view tld, std::optional<std::string> n = std::nullopt)
            : _pubkey{std::move(pk)}, _name{std::move(n)}, _tld{tld}
        {}
        RemoteAddr(const RemoteAddr& other) : RemoteAddr{other._pubkey, other._tld, other._name}
        {}
        RemoteAddr(RemoteAddr&& other)
            : RemoteAddr{std::move(other._pubkey), std::move(other._tld), std::move(other._name)}
        {}
        RemoteAddr& operator=(const RemoteAddr& other) = default;
        RemoteAddr& operator=(RemoteAddr&& other);

        bool operator<(const RemoteAddr& other) const;
        bool operator==(const RemoteAddr& other) const;
        bool operator!=(const RemoteAddr& other) const;

        virtual ~RemoteAddr() = default;

        std::string to_string() const
        {
            return remote_name();
        }

       protected:
        PublicKey _pubkey;
        std::optional<std::string> _name = std::nullopt;
        std::string _tld;

        std::string name() const
        {
            return _name.value_or(_pubkey.to_string());
        }

        std::string tld() const
        {
            return _tld;
        }

        std::string remote_name() const
        {
            return name() + tld();
        }

        /// This function currently assumes the remote address string is a pubkey, rather than
        /// an ONS name (TODO:)
        virtual bool from_pubkey_addr(std::string)
        {
            return true;
        }
    };

    struct RelayAddress final : public RemoteAddr
    {
        RelayAddress() = default;

        explicit RelayAddress(RelayPubKey rpk, std::optional<std::string> n = std::nullopt)
            : RemoteAddr{std::move(rpk), TLD::RELAY, std::move(n)}
        {}
        RelayAddress(const RelayAddress& other) : RemoteAddr{other._pubkey, TLD::RELAY, other._name}
        {}
        RelayAddress(RelayAddress&& other) : RemoteAddr{std::move(other._pubkey), TLD::RELAY, std::move(other._name)}
        {}
        RelayAddress& operator=(const RelayAddress& other) = default;
        RelayAddress& operator=(RelayAddress&& other);

        bool operator<(const RelayAddress& other) const;
        bool operator==(const RelayAddress& other) const;
        bool operator!=(const RelayAddress& other) const;

        ~RelayAddress() override = default;

        bool from_pubkey_addr(std::string arg) override;
    };

    struct ClientAddress final : public RemoteAddr
    {
        ClientAddress() = default;

        explicit ClientAddress(ClientPubKey cpk, std::optional<std::string> n = std::nullopt)
            : RemoteAddr{std::move(cpk), TLD::CLIENT, std::move(n)}
        {}
        ClientAddress(const ClientAddress& other) : RemoteAddr{other._pubkey, TLD::RELAY, other._name}
        {}
        ClientAddress(ClientAddress&& other) : RemoteAddr{std::move(other._pubkey), TLD::RELAY, std::move(other._name)}
        {}
        ClientAddress& operator=(const ClientAddress& other) = default;
        ClientAddress& operator=(ClientAddress&& other);

        bool operator<(const ClientAddress& other) const;
        bool operator==(const ClientAddress& other) const;
        bool operator!=(const ClientAddress& other) const;

        ~ClientAddress() override = default;

        bool from_pubkey_addr(std::string arg) override;
    };

    template <>
    inline constexpr bool IsToStringFormattable<RemoteAddr> = true;

    template <typename T>
    inline constexpr bool IsToStringFormattable<T, std::enable_if_t<std::is_base_of_v<RemoteAddr, T>>> = true;

}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::RemoteAddr>
    {
        virtual size_t operator()(const llarp::RemoteAddr& r) const
        {
            return std::hash<std::string>{}(r.to_string());
        }
    };

    template <>
    struct hash<llarp::RelayAddress> : public hash<llarp::RemoteAddr>
    {};

    template <>
    struct hash<llarp::ClientAddress> : public hash<llarp::RemoteAddr>
    {};
}  //  namespace std
