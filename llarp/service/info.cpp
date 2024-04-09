#include "info.hpp"

#include "address.hpp"

#include <llarp/crypto/crypto.hpp>

namespace llarp::service
{
    static auto logcat = log::Cat("service_info");

    bool ServiceInfo::verify(uint8_t* buf, size_t size, const Signature& sig) const
    {
        return crypto::verify(signkey, buf, size, sig);
    }

    bool ServiceInfo::update(const uint8_t* sign, const uint8_t* enc, const std::optional<VanityNonce>& nonce)
    {
        signkey = sign;
        enckey = enc;
        if (nonce)
        {
            vanity = *nonce;
        }

        return update_address();
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
            log::critical(logcat, "ServiceInfo failed to populate with bt encoded contents");
            throw;
        }
    }

    bool ServiceInfo::bt_decode(std::string_view buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};

            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "ServiceInfo parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }

        return true;
    }

    void ServiceInfo::bt_encode(oxenc::bt_dict_producer& btdp) const
    {
        btdp.append("e", enckey.to_view());
        btdp.append("s", signkey.to_view());

        if (not vanity.is_zero())
            btdp.append("x", vanity.to_view());
    }

    std::string ServiceInfo::name() const
    {
        if (_cached_addr.is_empty())
        {
            PubKey pk;
            calculate_address(pk);
            return pk.to_string();
        }

        return _cached_addr.to_string();
    }

    bool ServiceInfo::calculate_address(PubKey& data) const
    {
        data = PubKey{signkey.as_array()};
        return true;
    }

    bool ServiceInfo::update_address()
    {
        if (_cached_addr.is_empty())
        {
            return calculate_address(_cached_addr.pubkey());
        }

        return true;
    }

    std::string ServiceInfo::to_string() const
    {
        return fmt::format("[ServiceInfo e={} s={} v={} x={}]", enckey, signkey, version, vanity);
    }

}  // namespace llarp::service
