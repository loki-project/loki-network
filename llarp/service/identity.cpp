#include "identity.hpp"

#include <llarp/crypto/crypto.hpp>

namespace llarp::service
{
    static auto logcat = log::Cat("Identity");

    std::string Identity::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        btdp.append("s", _idkey.to_view());
        btdp.append("v", version);

        return std::move(btdp).str();
    }

    void Identity::bt_decode(std::string buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};

            _idkey.from_string(btdc.require<std::string>("s"));
            version = btdc.require<uint64_t>("v");
        }
        catch (...)
        {
            log::warning(logcat, "Identity failed to parse bt-encoded contents!");
            throw;
        }
    }

    void Identity::Clear()
    {
        _idkey.zero();
        _enckey.zero();
        derivedSignKey.zero();
    }

    void Identity::regenerate_keys()
    {
        crypto::identity_keygen(_idkey);
        crypto::encryption_keygen(_enckey);

        pub.update(seckey_to_pubkey(_idkey), seckey_to_pubkey(_enckey));

        if (not crypto::derive_subkey_private(derivedSignKey, _idkey, 1))
        {
            throw std::runtime_error("failed to derive subkey");
        }
    }

    bool Identity::KeyExchange(
        path_dh_func dh, SharedSecret& result, const ServiceInfo& other, const KeyExchangeNonce& N) const
    {
        return dh(result, other.encryption_pubkey(), _enckey, N);
    }

    bool Identity::Sign(Signature& sig, uint8_t* buf, size_t size) const
    {
        return crypto::sign(sig, _idkey, buf, size);
    }

    std::optional<EncryptedIntroSet> Identity::encrypt_and_sign_introset(
        const IntroSetOld& other_i, std::chrono::milliseconds now) const
    {
        EncryptedIntroSet encrypted;

        if (other_i.intros.empty())
            return std::nullopt;

        IntroSetOld i{other_i};
        encrypted.nonce.Randomize();
        // set timestamp
        // TODO: round to nearest 1000 ms
        i.time_signed = now;
        encrypted.signed_at = now;
        // set service info
        i.address_keys = pub;

        auto bte = i.bt_encode();

        const SharedSecret k{i.address_keys.address().pubkey()};
        crypto::xchacha20(reinterpret_cast<uint8_t*>(bte.data()), bte.size(), k, encrypted.nonce);

        std::memcpy(encrypted.introset_payload.data(), bte.data(), bte.size());

        if (not encrypted.sign(derivedSignKey))
            return std::nullopt;
        return encrypted;
    }
}  // namespace llarp::service
