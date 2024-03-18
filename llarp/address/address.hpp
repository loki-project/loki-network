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
    template <typename pubkey_t = PubKey, std::enable_if_t<std::is_base_of_v<PubKey, pubkey_t>, int> = 0>
    struct RemoteAddress
    {
        pubkey_t _pubkey;
        std::optional<std::string> _name = std::nullopt;
        std::string _tld;
        bool is_ons{false};

        RemoteAddress() = default;

        explicit RemoteAddress(std::string addr, bool _is_ons = false) : _name{std::move(addr)}, is_ons{_is_ons}
        {
            if (not is_ons)
                _pubkey.from_string(*_name);

            if constexpr (std::is_same_v<pubkey_t, ClientPubKey>)
                _tld = std::string{TLD::CLIENT};
            else if constexpr (std::is_same_v<pubkey_t, RelayPubKey>)
                _tld = std::string{TLD::RELAY};
            else
                throw std::invalid_argument{"Something seriously weird just happened."};
        }

        explicit RemoteAddress(PubKey pk, std::string_view tld, std::optional<std::string> n = std::nullopt)
            : _pubkey{pk.data()}, _name{std::move(n)}, _tld{tld}
        {}
        RemoteAddress(const RemoteAddress& other) : RemoteAddress{other._pubkey, other._tld, other._name}
        {}
        RemoteAddress(RemoteAddress&& other)
            : RemoteAddress{std::move(other._pubkey), std::move(other._tld), std::move(other._name)}
        {}

        RemoteAddress& operator=(const RemoteAddress& other) = default;

        RemoteAddress& operator=(RemoteAddress&& other)
        {
            _pubkey = std::move(other._pubkey);
            _name = std::move(other._name);
            _tld = std::move(other._tld);
            return *this;
        }

        bool operator<(const RemoteAddress& other) const
        {
            return std::tie(_pubkey, _name, _tld) < std::tie(other._pubkey, other._name, other._tld);
        }
        bool operator==(const RemoteAddress& other) const
        {
            return _pubkey == other._pubkey and _name == other._name && _tld == other._tld;
        }
        bool operator!=(const RemoteAddress& other) const
        {
            return not(*this == other);
        }

        ~RemoteAddress() = default;

        std::string to_string() const
        {
            return remote_name();
        }

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
    };

    template <typename pubkey_t = PubKey, std::enable_if_t<std::is_base_of_v<PubKey, pubkey_t>, int> = 0>
    std::optional<RemoteAddress<pubkey_t>> from_pubkey_addr(const std::string& arg)
    {
        if constexpr (std::is_same_v<pubkey_t, ClientPubKey> || std::is_same_v<pubkey_t, PubKey>)
        {
            if (service::is_valid_ons(arg))
            {
                return std::make_optional(RemoteAddress<ClientPubKey>(arg, true));
            }
            if (auto maybe_addr = parse_addr_string(arg, TLD::CLIENT))
            {
                return std::make_optional(RemoteAddress<ClientPubKey>(*maybe_addr));
            }
        }
        if (auto maybe_addr = parse_addr_string(arg, TLD::RELAY))
        {
            return std::make_optional(RemoteAddress<RelayPubKey>(*maybe_addr));
        }

        return std::nullopt;
    }
    template <typename pk_t>
    inline constexpr bool IsToStringFormattable<RemoteAddress<pk_t>> = true;
}  // namespace llarp

namespace std
{
    template <typename pk_t>
    struct hash<llarp::RemoteAddress<pk_t>>
    {
        virtual size_t operator()(const llarp::RemoteAddress<pk_t>& r) const
        {
            return std::hash<std::string>{}(r.to_string());
        }
    };
}  //  namespace std
