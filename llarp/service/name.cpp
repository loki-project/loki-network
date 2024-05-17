#include "name.hpp"

#include <llarp/address/address.hpp>
#include <llarp/crypto/crypto.hpp>

namespace llarp::service
{
    static auto logcat = llarp::log::Cat("ONSRecord");

    std::optional<EncryptedONSRecord> EncryptedONSRecord::construct(std::string bt)
    {
        if (EncryptedONSRecord ret; ret.bt_decode(std::move(bt)))
            return ret;

        return std::nullopt;
    }

    EncryptedONSRecord::EncryptedONSRecord(std::string bt)
    {
        try
        {
            // The constructor calls the ::bt_decode() overload that re-throws any exception it hits
            oxenc::bt_dict_consumer btdc{bt};
            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "EncryptedONSRecord exception: {}", e.what());
        }
    }

    bool EncryptedONSRecord::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            ciphertext = btdc.require<std::string>("c");
            nonce.from_string(btdc.require<std::string>("n"));

            return true;
        }
        catch (...)
        {
            log::warning(logcat, "EncryptedONSRecord exception");
            throw;
        }
    }

    bool EncryptedONSRecord::bt_decode(std::string bt)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{bt};
            return bt_decode(btdc);
        }
        catch (...)
        {
            log::warning(logcat, "EncryptedONSRecord exception");
            return false;
        }
    }

    std::string EncryptedONSRecord::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        btdp.append("c", ciphertext);
        btdp.append("n", nonce.to_view());

        return std::move(btdp).str();
    }

    std::optional<NetworkAddress> EncryptedONSRecord::decrypt(std::string_view ons_name) const
    {
        std::optional<NetworkAddress> ret = std::nullopt;

        if (ciphertext.empty())
            return ret;

        if (auto maybe = crypto::maybe_decrypt_name(ciphertext, nonce, ons_name))
        {
            auto _name = "{}.loki"_format(maybe->to_view());
            ret = NetworkAddress::from_network_addr(std::move(_name));
        }

        return ret;
    }
}  // namespace llarp::service
