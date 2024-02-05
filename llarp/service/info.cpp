#include "info.hpp"

#include "address.hpp"

#include <llarp/crypto/crypto.hpp>

namespace llarp::service
{
    bool ServiceInfo::verify(uint8_t* buf, size_t size, const Signature& sig) const
    {
        return crypto::verify(signkey, buf, size, sig);
    }

    bool ServiceInfo::Update(const uint8_t* sign, const uint8_t* enc, const std::optional<VanityNonce>& nonce)
    {
        signkey = sign;
        enckey = enc;
        if (nonce)
        {
            vanity = *nonce;
        }
        return UpdateAddr();
    }

    bool ServiceInfo::decode_key(const llarp_buffer_t& key, llarp_buffer_t* val)
    {
        bool read = false;
        if (!BEncodeMaybeReadDictEntry("e", enckey, read, key, val))
            return false;
        if (!BEncodeMaybeReadDictEntry("s", signkey, read, key, val))
            return false;
        if (!BEncodeMaybeReadDictInt("v", version, read, key, val))
            return false;
        if (!BEncodeMaybeReadDictEntry("x", vanity, read, key, val))
            return false;
        return read;
    }

    void ServiceInfo::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            enckey.from_hex(btdc.require<std::string>("e"));
            signkey.from_hex(btdc.require<std::string>("s"));
            vanity.from_string(btdc.require<std::string>("x"));
        }
        catch (...)
        {
            log::critical(info_cat, "ServiceInfo failed to populate with bt encoded contents");
        }
    }

    void ServiceInfo::bt_encode(oxenc::bt_dict_producer& btdp) const
    {
        btdp.append("e", enckey.ToView());
        btdp.append("s", signkey.ToView());

        if (not vanity.IsZero())
            btdp.append("x", vanity.ToView());
    }

    std::string ServiceInfo::Name() const
    {
        if (_cached_addr.IsZero())
        {
            Address addr;
            CalculateAddress(addr.as_array());
            return addr.to_string();
        }
        return _cached_addr.to_string();
    }

    bool ServiceInfo::CalculateAddress(std::array<uint8_t, 32>& data) const
    {
        data = signkey.as_array();
        return true;
    }

    bool ServiceInfo::UpdateAddr()
    {
        if (_cached_addr.IsZero())
        {
            return CalculateAddress(_cached_addr.as_array());
        }
        return true;
    }

    std::string ServiceInfo::to_string() const
    {
        return fmt::format("[ServiceInfo e={} s={} v={} x={}]", enckey, signkey, version, vanity);
    }

}  // namespace llarp::service
