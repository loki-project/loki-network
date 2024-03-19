#include "address.hpp"

#include "utils.hpp"

namespace llarp
{
    static auto logcat = log::Cat("address");

    std::optional<ClientAddress> ClientAddress::from_client_addr(std::string arg)
    {
        std::optional<ClientAddress> ret = std::nullopt;

        if (not arg.ends_with(".loki"))
            log::warning(logcat, "Invalid ClientAddress constructor input lacking '.loki' (input:{})", arg);
        else
            ret = ClientAddress{arg, service::is_valid_ons(arg)};

        return ret;
    }

    ClientAddress::ClientAddress(std::string_view arg, bool is_ons) : RemoteAddress{TLD::CLIENT}, _is_ons{is_ons}
    {
        // This private constructor is only called after checking for a '.loki' suffix; only Santa checks twice
        arg.remove_suffix(5);

        // If this was constructed using an ONS name, we don't fill in the pubkey
        if (not _is_ons)
            _pubkey->from_string(arg);
        else
            _name = arg;
    }

    bool ClientAddress::operator<(const ClientAddress& other) const
    {
        return std::tie(_pubkey, _name, _is_ons) < std::tie(other._pubkey, other._name, other._is_ons);
    }

    bool ClientAddress::operator==(const ClientAddress& other) const
    {
        return std::tie(_pubkey, _name, _is_ons) == std::tie(other._pubkey, other._name, other._is_ons);
    }

    bool ClientAddress::operator!=(const ClientAddress& other) const
    {
        return !(*this == other);
    }

    std::optional<RelayAddress> RelayAddress::from_relay_addr(std::string arg)
    {
        std::optional<RelayAddress> ret = std::nullopt;

        if (not arg.ends_with(".snode"))
            log::warning(logcat, "Invalid RelayAddress constructor input lacking '.loki' (input:{})", arg);
        else
            ret = RelayAddress{arg};

        return ret;
    }

    RelayAddress::RelayAddress(std::string_view arg) : RemoteAddress{TLD::RELAY}
    {
        // This private constructor is only called after checking for a '.loki' suffix; only Santa checks twice
        arg.remove_suffix(6);
        _pubkey.from_string(arg);
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
