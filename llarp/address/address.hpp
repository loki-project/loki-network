#pragma once

#include "utils.hpp"

#include <llarp/contact/keys.hpp>
#include <llarp/contact/router_id.hpp>
#include <llarp/contact/sns.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/concept.hpp>

#include <oxen/quic.hpp>

#include <utility>

namespace llarp
{
    /** NOTE:
        - These classes are purposely differentiated at the moment. At first pass, they seem like they could be easily
            combined into one shared class utilizing some sort of variant or templating
        - This may eventually be true, but the currently enforced heterogeneity is intended to leave space for a
            near-future replacement of RouterID and PubKey with ClientKey and RelayKey
    */

    /** NetworkAddress:
        This address type conceptually encapsulates any addressible hidden service or exit node operating on the
        network. This type is to be strictly used in contexts referring to remote exit nodes or hidden services
        operated on clients and clients/relays respectively. It can be constructed a few specific ways:
            - static ::from_network_addr(...) : this function expects a network address string terminated in '.loki'
                or '.snode'.
    */
    struct NetworkAddress
    {
      private:
        PubKey _pubkey;

        bool _is_client{false};
        std::string _tld;

        // This private constructor expects a '.snode' or '.loki' suffix
        explicit NetworkAddress(std::string_view addr, std::string_view tld);

        // This private constructor expects NO '.snode' or '.loki' suffix
        explicit NetworkAddress(RouterID rid, bool is_client) : _pubkey{std::move(rid)}, _is_client{is_client} {}

      public:
        NetworkAddress() = default;
        ~NetworkAddress() = default;

        NetworkAddress(const NetworkAddress& other) = default;
        NetworkAddress(NetworkAddress&& other) = default;

        NetworkAddress& operator=(const NetworkAddress& other) = default;
        NetworkAddress& operator=(NetworkAddress&& other) = default;

        bool operator<(const NetworkAddress& other) const;
        bool operator==(const NetworkAddress& other) const;
        bool operator!=(const NetworkAddress& other) const;

        bool is_empty() const { return _pubkey.is_zero() and _tld.empty(); }

        // Will throw invalid_argument with bad input. Assumes that the network address terminates in either '.loki'
        // or '.snode'
        static std::optional<NetworkAddress> from_network_addr(std::string_view arg);

        // Assumes that the pubkey passed is NOT terminated in either a '.loki' or '.snode' suffix
        static NetworkAddress from_pubkey(const RouterID& rid, bool is_client);

        bool is_client() const { return _is_client; }

        bool is_relay() const { return !is_client(); }

        const PubKey& pubkey() const { return _pubkey; }

        PubKey& pubkey() { return _pubkey; }

        const RouterID& router_id() const { return static_cast<const RouterID&>(pubkey()); }

        RouterID& router_id() { return static_cast<RouterID&>(pubkey()); }

        std::string name() const { return _pubkey.to_string(); }

        std::string to_string() const { return name().append(_tld); }
        static constexpr bool to_string_formattable{true};
    };

    /** RelayAddress:
        This address object encapsulates the concept of an addressible service node operating on the network as a
        lokinet relay. This object is NOT meant to be used in any scope referring to a hidden service or exit node
        being operated on that remote relay (not that service nodes operate exit nodes anyways) -- for that, use the
        above NetworkAddress type.

        This object will become more differentiated from NetworkAddress once {Relay,Client}PubKey is implemented.
        That is a whole other can of worms...
    */
    struct RelayAddress
    {
      private:
        PubKey _pubkey;

        explicit RelayAddress(std::string_view addr);

      public:
        RelayAddress() = default;
        ~RelayAddress() = default;

        explicit RelayAddress(PubKey cpk) : _pubkey{std::move(cpk)} {}

        RelayAddress(const RelayAddress& other) = default;

        RelayAddress(RelayAddress&& other) : _pubkey{std::move(other._pubkey)} {}

        RelayAddress& operator=(const RelayAddress& other) = default;
        RelayAddress& operator=(RelayAddress&& other) = default;

        bool operator<(const RelayAddress& other) const;
        bool operator==(const RelayAddress& other) const;
        bool operator!=(const RelayAddress& other) const;

        // Will throw invalid_argument with bad input
        static std::optional<RelayAddress> from_relay_addr(std::string arg);

        const PubKey& pubkey() const { return _pubkey; }

        PubKey& pubkey() { return _pubkey; }

        const RouterID& router_id() const { return static_cast<const RouterID&>(pubkey()); }

        RouterID& router_id() { return static_cast<RouterID&>(pubkey()); }

        std::string to_string() const { return _pubkey.to_string().append(TLD::SNODE); }

        static constexpr bool to_string_formattable = true;
    };

    namespace concepts
    {
        template <typename addr_t>
        concept NetworkAddrType = std::is_base_of_v<NetworkAddress, addr_t>;
    };  // namespace concepts

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
