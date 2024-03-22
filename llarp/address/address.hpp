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
    struct RemoteAddress
    {
      protected:
        std::string _tld;

        explicit RemoteAddress(std::string_view tld) : _tld{std::move(tld)}
        {}

        virtual std::string pub_key() const = 0;

      public:
        RemoteAddress() = default;
        virtual ~RemoteAddress() = default;

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
    concept RemoteAddrType = std::is_base_of_v<RemoteAddress, addr_t>;

    struct ClientAddress final : public RemoteAddress
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
            : RemoteAddress{TLD::CLIENT}, _pubkey{std::move(cpk)}, _name{std::move(n)}
        {}

        ClientAddress(const ClientAddress& other)
            : RemoteAddress{TLD::RELAY}, _pubkey{other._pubkey}, _name{other._name}
        {}

        ClientAddress(ClientAddress&& other)
            : RemoteAddress{TLD::RELAY}, _pubkey{std::move(other._pubkey)}, _name{std::move(other._name)}
        {}

        ClientAddress& operator=(const ClientAddress& other) = default;
        ClientAddress& operator=(ClientAddress&& other) = default;

        bool operator<(const ClientAddress& other) const;
        bool operator==(const ClientAddress& other) const;
        bool operator!=(const ClientAddress& other) const;

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

    struct RelayAddress final : public RemoteAddress
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

        explicit RelayAddress(RelayPubKey cpk) : RemoteAddress{TLD::CLIENT}, _pubkey{std::move(cpk)}
        {}

        RelayAddress(const RelayAddress& other) : RemoteAddress{TLD::RELAY}, _pubkey{other._pubkey}
        {}

        RelayAddress(RelayAddress&& other) : RemoteAddress{TLD::RELAY}, _pubkey{std::move(other._pubkey)}
        {}

        RelayAddress& operator=(const RelayAddress& other) = default;
        RelayAddress& operator=(RelayAddress&& other) = default;

        bool operator<(const RelayAddress& other) const;
        bool operator==(const RelayAddress& other) const;
        bool operator!=(const RelayAddress& other) const;

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

    template <>
    inline constexpr bool IsToStringFormattable<RemoteAddress> = true;

    template <typename T>
    inline constexpr bool IsToStringFormattable<T, std::enable_if_t<std::is_base_of_v<RemoteAddress, T>>> = true;
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::RemoteAddress>
    {
        virtual size_t operator()(const llarp::RemoteAddress& r) const
        {
            return std::hash<std::string>{}(r.to_string());
        }
    };

    template <>
    struct hash<llarp::RelayAddress> : public hash<llarp::RemoteAddress>
    {};

    template <>
    struct hash<llarp::ClientAddress> : public hash<llarp::RemoteAddress>
    {};
}  //  namespace std
