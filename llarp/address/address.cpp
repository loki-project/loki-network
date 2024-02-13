#include "address.hpp"

#include "utils.hpp"

namespace llarp
{
    auto parse_addr_string = [](std::string_view arg, std::string_view tld) -> std::optional<std::string> {
        std::optional<std::string> ret = std::nullopt;

        if (auto pos = arg.find_first_of('.'); pos != std::string_view::npos)
        {
            auto _prefix = arg.substr(0, pos);
            // check the pubkey prefix is the right length
            if (_prefix.length() != PUBKEYSIZE)
                return ret;

            // verify the tld is allowed
            auto _tld = arg.substr(pos + 1);

            if (_tld == tld and TLD::allowed.count(_tld))
                ret = _prefix;
        }

        return ret;
    };

    RemoteAddr& RemoteAddr::operator=(RemoteAddr&& other)
    {
        _pubkey = std::move(other._pubkey);
        _name = std::move(other._name);
        _tld = std::move(other._tld);
        return *this;
    }

    bool RemoteAddr::operator<(const RemoteAddr& other) const
    {
        return std::tie(_pubkey, _name, _tld) < std::tie(other._pubkey, other._name, other._tld);
    }

    bool RemoteAddr::operator==(const RemoteAddr& other) const
    {
        return _pubkey == other._pubkey and _name == other._name && _tld == other._tld;
    }

    bool RemoteAddr::operator!=(const RemoteAddr& other) const
    {
        return not(*this == other);
    }

    RelayAddress& RelayAddress::operator=(RelayAddress&& other)
    {
        _pubkey = std::move(other._pubkey);
        _name = std::move(other._name);
        _tld = std::move(other._tld);
        return *this;
    }

    bool RelayAddress::operator<(const RelayAddress& other) const
    {
        return std::tie(_pubkey, _name, _tld) < std::tie(other._pubkey, other._name, other._tld);
    }

    bool RelayAddress::operator==(const RelayAddress& other) const
    {
        return _pubkey == other._pubkey and _name == other._name && _tld == other._tld;
    }

    bool RelayAddress::operator!=(const RelayAddress& other) const
    {
        return not(*this == other);
    }

    ClientAddress& ClientAddress::operator=(ClientAddress&& other)
    {
        _pubkey = std::move(other._pubkey);
        _name = std::move(other._name);
        _tld = std::move(other._tld);
        return *this;
    }

    bool ClientAddress::operator<(const ClientAddress& other) const
    {
        return std::tie(_pubkey, _name, _tld) < std::tie(other._pubkey, other._name, other._tld);
    }

    bool ClientAddress::operator==(const ClientAddress& other) const
    {
        return _pubkey == other._pubkey and _name == other._name && _tld == other._tld;
    }

    bool ClientAddress::operator!=(const ClientAddress& other) const
    {
        return not(*this == other);
    }

    bool RelayAddress::from_pubkey_addr(std::string arg)
    {
        if (auto maybe_addr = parse_addr_string(arg, TLD::RELAY))
        {
            _pubkey.from_string(*maybe_addr);
            _tld = TLD::RELAY;
            return true;
        }

        return false;
    }

    bool ClientAddress::from_pubkey_addr(std::string arg)
    {
        if (auto maybe_addr = parse_addr_string(arg, TLD::CLIENT))
        {
            _pubkey.from_string(*maybe_addr);
            _tld = TLD::CLIENT;
            return true;
        }

        return false;
    }

}  //  namespace llarp
