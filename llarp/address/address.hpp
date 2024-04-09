#pragma once

#include "keys.hpp"
#include "utils.hpp"

#include <llarp/service/name.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/concept.hpp>
#include <llarp/util/fs.hpp>

#include <oxen/quic.hpp>

#include <utility>

namespace llarp
{
    /** NetworkAddress:
        This address type conceptually encapsulates any addressible hidden service or exit node operating on the
        network. This type is to be strictly used in contexts referring to remote exit nodes or hidden services
        operated on clients and clients/relays respectively. It can be constructed a few specific ways:
            - static ::from_network_addr(...) : this function expects a network address string terminated in '.loki'
                or '.snode'.
            - {Client,Relay}PubKey : these and the copy/move constructors cascade into the private constructor
    */
    struct NetworkAddress
    {
      private:
        PubKey _pubkey;

        std::string _tld;
        bool _is_client{false};

        explicit NetworkAddress(std::string_view addr, std::string_view tld);

      public:
        template <RemotePubKeyType pubkey_t>
        explicit NetworkAddress(pubkey_t pubkey, std::string_view tld) : NetworkAddress{pubkey.to_view(), tld}
        {}

        NetworkAddress() = default;
        ~NetworkAddress() = default;

        explicit NetworkAddress(RelayPubKey rpk) : NetworkAddress{rpk, TLD::SNODE}
        {}

        explicit NetworkAddress(ClientPubKey cpk) : NetworkAddress{cpk, TLD::LOKI}
        {}

        NetworkAddress(const NetworkAddress& other) : NetworkAddress{other._pubkey, other._tld}
        {}

        NetworkAddress(NetworkAddress&& other) : NetworkAddress{std::move(other._pubkey), std::move(other._tld)}
        {}

        NetworkAddress& operator=(const NetworkAddress& other) = default;
        NetworkAddress& operator=(NetworkAddress&& other) = default;

        bool operator<(const NetworkAddress& other) const;
        bool operator==(const NetworkAddress& other) const;
        bool operator!=(const NetworkAddress& other) const;

        // Will throw invalid_argument with bad input. Assumes that the network address terminates in either '.loki'
        // or '.snode'
        static std::optional<NetworkAddress> from_network_addr(std::string arg);

        bool is_client() const
        {
            return _is_client;
        }

        bool is_relay() const
        {
            return !is_client();
        }

        const PubKey& pubkey() const
        {
            return _pubkey;
        }

        PubKey pubkey()
        {
            return _pubkey;
        }

        std::string name() const
        {
            return _pubkey.to_string();
        }

        std::string to_string() const
        {
            return name().append(_tld);
        }
    };

    /** RelayAddress:
        This address object encapsulates the concept of an addressible service node operating on the network as a
        lokinet relay. This object is NOT meant to be used in any scope referring to a hidden service or exit node
        being operated on that remote relay (not that service nodes operate exit nodes anyways) -- for that, use the
        above NetworkAddress type.
    */
    struct RelayAddress
    {
      private:
        RelayPubKey _pubkey;

        explicit RelayAddress(std::string_view addr);

      public:
        RelayAddress() = default;
        ~RelayAddress() = default;

        explicit RelayAddress(RelayPubKey cpk) : _pubkey{std::move(cpk)}
        {}

        RelayAddress(const RelayAddress& other) = default;

        RelayAddress(RelayAddress&& other) : _pubkey{std::move(other._pubkey)}
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

        std::string to_string() const
        {
            return _pubkey.to_string().append(TLD::SNODE);
        }
    };

    template <typename addr_t>
    concept CONCEPT_COMPAT NetworkAddrType = std::is_base_of_v<NetworkAddress, addr_t>;

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
    struct hash<llarp::RelayAddress>
    {
        virtual size_t operator()(const llarp::RelayAddress& r) const
        {
            return std::hash<std::string>{}(r.to_string());
        }
    };
}  //  namespace std
