#include "keys.hpp"

#include <oxenc/hex.h>

namespace llarp
{
    std::string PublicKey::to_string() const
    {
        return oxenc::to_hex(begin(), end());
    }

    PublicKey& PublicKey::operator=(const PublicKey& other)
    {
        std::memcpy(begin(), other.begin(), PUBKEYSIZE);
        return *this;
    }

    bool PublicKey::operator<(const PublicKey& other) const
    {
        return as_array() < other.as_array();
    }

    bool PublicKey::operator==(const PublicKey& other) const
    {
        return as_array() == other.as_array();
    }

    bool PublicKey::operator!=(const PublicKey& other) const
    {
        return !(*this == other);
    }

    std::string RelayPubKey::to_string() const
    {
        return oxenc::to_hex(begin(), end());
    }

    RelayPubKey& RelayPubKey::operator=(const RelayPubKey& other)
    {
        std::memcpy(begin(), other.begin(), PUBKEYSIZE);
        return *this;
    }

    bool RelayPubKey::operator<(const RelayPubKey& other) const
    {
        return as_array() < other.as_array();
    }

    bool RelayPubKey::operator==(const RelayPubKey& other) const
    {
        return as_array() == other.as_array();
    }

    bool RelayPubKey::operator!=(const RelayPubKey& other) const
    {
        return !(*this == other);
    }

    std::string ClientPubKey::to_string() const
    {
        return oxenc::to_hex(begin(), end());
    }

    bool ClientPubKey::operator<(const ClientPubKey& other) const
    {
        return as_array() < other.as_array();
    }

    bool ClientPubKey::operator==(const ClientPubKey& other) const
    {
        return as_array() == other.as_array();
    }

    bool ClientPubKey::operator!=(const ClientPubKey& other) const
    {
        return !(*this == other);
    }

    ClientPubKey& ClientPubKey::operator=(const ClientPubKey& other)
    {
        std::memcpy(begin(), other.begin(), PUBKEYSIZE);
        return *this;
    }

}  // namespace llarp
