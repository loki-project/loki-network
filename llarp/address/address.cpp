#include "address.hpp"

#include "utils.hpp"

namespace llarp
{
    static auto logcat = log::Cat("address");

    std::optional<NetworkAddress> NetworkAddress::from_network_addr(std::string_view arg)
    {
        std::optional<NetworkAddress> ret = std::nullopt;

        if (arg.ends_with(TLD::SNODE))
        {
            ret = NetworkAddress{arg, TLD::SNODE};
        }
        else if (arg.ends_with(TLD::LOKI))
        {
            ret = NetworkAddress{arg, TLD::LOKI};
        }
        else
            log::warning(logcat, "Invalid NetworkAddress constructor input (arg:{})", arg);

        return ret;
    }

    NetworkAddress NetworkAddress::from_pubkey(const RouterID& rid, bool is_client)
    {
        return NetworkAddress{rid, is_client};
    }

    NetworkAddress::NetworkAddress(std::string_view arg, std::string_view tld) : _tld{tld}
    {
        if (not _pubkey.from_string(arg.substr(0, _tld.size())))
            throw std::invalid_argument{"Invalid pubkey passed to NetworkAddress constructor: {}"_format(arg)};

        _is_client = tld == TLD::LOKI;
    }

    bool NetworkAddress::operator<(const NetworkAddress& other) const
    {
        return std::tie(_pubkey, _is_client) < std::tie(other._pubkey, other._is_client);
    }

    bool NetworkAddress::operator==(const NetworkAddress& other) const
    {
        return std::tie(_pubkey, _is_client) == std::tie(other._pubkey, other._is_client);
    }

    bool NetworkAddress::operator!=(const NetworkAddress& other) const
    {
        return !(*this == other);
    }

    std::optional<RelayAddress> RelayAddress::from_relay_addr(std::string arg)
    {
        std::optional<RelayAddress> ret = std::nullopt;

        if (not arg.ends_with(".snode"))
            log::warning(logcat, "Invalid RelayAddress constructor input lacking '.snode' (input:{})", arg);
        else
            ret = RelayAddress{arg};

        return ret;
    }

    RelayAddress::RelayAddress(std::string_view arg)
    {
        // This private constructor is only called after checking for a '.snode' suffix; only Santa checks twice
        arg.remove_suffix(6);

        if (not _pubkey.from_string(arg))
            throw std::invalid_argument{"Invalid pubkey passed to RelayAddress constructor: {}"_format(arg)};
    }

    bool RelayAddress::operator<(const RelayAddress& other) const
    {
        return _pubkey < other._pubkey;
    }

    bool RelayAddress::operator==(const RelayAddress& other) const
    {
        return _pubkey == other._pubkey;
    }

    bool RelayAddress::operator!=(const RelayAddress& other) const
    {
        return !(*this == other);
    }
}  //  namespace llarp
