#include "sns.hpp"

#include <llarp/address/address.hpp>
#include <llarp/crypto/crypto.hpp>

namespace llarp
{
    static auto logcat = llarp::log::Cat("ONSRecord");

    EncryptedSNSRecord EncryptedSNSRecord::deserialize(std::string_view bt)
    {
        return EncryptedSNSRecord{bt};
    }

    EncryptedSNSRecord::EncryptedSNSRecord(std::string_view bt) : _bt_payload{bt}
    {
        bt_decode(oxenc::bt_dict_consumer{_bt_payload});
    }

    void EncryptedSNSRecord::bt_decode(oxenc::bt_dict_consumer&& btdc)
    {
        try
        {
            ciphertext = btdc.require<std::string>("c");
            nonce.from_string(btdc.require<std::string>("n"));
        }
        catch (...)
        {
            log::warning(logcat, "EncryptedSNSRecord exception");
            throw;
        }
    }

    std::string EncryptedSNSRecord::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        btdp.append("c", ciphertext);
        btdp.append("n", nonce.to_view());

        return std::move(btdp).str();
    }

    std::optional<NetworkAddress> EncryptedSNSRecord::decrypt(std::string_view ons_name) const
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
}  // namespace llarp
