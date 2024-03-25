#pragma once

#include "keys.hpp"
#include "utils.hpp"

#include <llarp/service/name.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/fs.hpp>

#include <oxen/quic.hpp>

#include <utility>

namespace llarp
{
    struct NetworkAddress
    {
      protected:
        std::string _tld;

        explicit NetworkAddress(std::string_view tld) : _tld{std::move(tld)}
        {}

        virtual std::string pub_key() const = 0;

      public:
        NetworkAddress() = default;
        virtual ~NetworkAddress() = default;

        std::string to_string() const
        {
            return remote_name();
        }

        virtual std::string name() const = 0;

        std::string tld() const
        {
            return _tld;
        }

        std::string remote_name() const
        {
            return name() + tld();
        }

        std::string remote_address() const
        {
            return pub_key() + tld();
        }
    };

    template <typename addr_t>
    concept
#if (!(defined(__clang__)) && defined(__GNUC__) && __GNUC__ < 10)
        bool
#endif
            NetworkAddrType = std::is_base_of_v<NetworkAddress, addr_t>;

    struct ClientAddress final : public NetworkAddress
    {
      private:
        std::optional<ClientPubKey> _pubkey{std::nullopt};
        std::optional<std::string> _name{std::nullopt};
        bool _is_ons{false};

        explicit ClientAddress(std::string_view addr, bool is_ons);

      protected:
        std::string pub_key() const override
        {
            return _pubkey ? _pubkey->to_string() : name();
        }

      public:
        ClientAddress() = default;
        ~ClientAddress() override = default;

        explicit ClientAddress(ClientPubKey cpk, std::optional<std::string> n = std::nullopt)
            : NetworkAddress{TLD::CLIENT}, _pubkey{std::move(cpk)}, _name{std::move(n)}
        {}

        ClientAddress(const ClientAddress& other)
            : NetworkAddress{TLD::RELAY}, _pubkey{other._pubkey}, _name{other._name}
        {}

        ClientAddress(ClientAddress&& other)
            : NetworkAddress{TLD::RELAY}, _pubkey{std::move(other._pubkey)}, _name{std::move(other._name)}
        {}

        ClientAddress& operator=(const ClientAddress& other) = default;
        ClientAddress& operator=(ClientAddress&& other) = default;

        bool operator<(const ClientAddress& other) const;
        bool operator==(const ClientAddress& other) const;
        bool operator!=(const ClientAddress& other) const;

        // Will throw invalid_argument with bad input
        static std::optional<ClientAddress> from_client_addr(std::string arg);

        bool set_pubkey(std::string pk)
        {
            return _pubkey->from_string(std::move(pk));
        }

        bool set_pubkey(std::string_view pk)
        {
            return _pubkey->from_string(pk);
        }

        std::optional<ClientPubKey> pubkey()
        {
            return _pubkey;
        }

        bool is_ons() const
        {
            return _is_ons;
        }

        std::string name() const override
        {
            return _name.value_or(_pubkey->to_string());
        }
    };

    struct RelayAddress final : public NetworkAddress
    {
      private:
        RelayPubKey _pubkey;

        explicit RelayAddress(std::string_view addr);

      protected:
        std::string pub_key() const override
        {
            return _pubkey.to_string();
        }

      public:
        RelayAddress() = default;
        ~RelayAddress() override = default;

        explicit RelayAddress(RelayPubKey cpk) : NetworkAddress{TLD::CLIENT}, _pubkey{std::move(cpk)}
        {}

        RelayAddress(const RelayAddress& other) : NetworkAddress{TLD::RELAY}, _pubkey{other._pubkey}
        {}

        RelayAddress(RelayAddress&& other) : NetworkAddress{TLD::RELAY}, _pubkey{std::move(other._pubkey)}
        {}

        RelayAddress& operator=(const RelayAddress& other) = default;
        RelayAddress& operator=(RelayAddress&& other) = default;

        bool operator<(const RelayAddress& other) const;
        bool operator==(const RelayAddress& other) const;
        bool operator!=(const RelayAddress& other) const;

        // Will throw invalid_argument with bad input
        static std::optional<RelayAddress> from_relay_addr(std::string arg);

        const RelayPubKey& pubkey()
        {
            return _pubkey;
        }

        std::string name() const override
        {
            return _pubkey.to_string();
        }
    };
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::NetworkAddress>
    {
        virtual size_t operator()(const llarp::NetworkAddress& r) const
        {
            return std::hash<std::string>{}(r.to_string());
        }
    };

    template <>
    struct hash<llarp::RelayAddress> : public hash<llarp::NetworkAddress>
    {};

    template <>
    struct hash<llarp::ClientAddress> : public hash<llarp::NetworkAddress>
    {};
}  //  namespace std
