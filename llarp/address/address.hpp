#pragma once

#include "keys.hpp"
#include "utils.hpp"

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

        RemoteAddress() = default;

        explicit RemoteAddress(std::string addr) : _name{std::move(addr)}
        {
            _pubkey.from_string(*_name);

            if constexpr (std::is_same_v<pubkey_t, ClientPubKey>)
                _tld = std::string{TLD::CLIENT};
            else if constexpr (std::is_same_v<pubkey_t, RelayPubKey>)
                _tld = std::string{TLD::RELAY};
            else
                throw std::invalid_argument{"Something seriously weird just happened."};
        }

        explicit RemoteAddress(PubKey pk, std::string_view tld, std::optional<std::string> n = std::nullopt)
            : _pubkey{std::move(pk)}, _name{std::move(n)}, _tld{tld}
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

    /// This function currently assumes the remote address string is a pubkey, rather than
    /// an ONS name (TODO:)
    template <typename pubkey_t>
    std::optional<RemoteAddress<pubkey_t>> from_pubkey_addr(const std::string& arg)
    {
        if (auto maybe_addr = parse_addr_string(arg, TLD::CLIENT))
        {
            return RemoteAddress<ClientPubKey>(*maybe_addr);
        }
        if (auto maybe_addr = parse_addr_string(arg, TLD::RELAY))
        {
            return RemoteAddress<RelayPubKey>(*maybe_addr);
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
