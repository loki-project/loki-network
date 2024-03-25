#include "identity.hpp"

#include <llarp/config/key_manager.hpp>
#include <llarp/crypto/crypto.hpp>

namespace llarp::service
{
    static auto logcat = log::Cat("Identity");

    std::string Identity::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        btdp.append("s", signkey.ToView());
        btdp.append("v", version);

        return std::move(btdp).str();
    }

    void Identity::bt_decode(std::string buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};

            signkey.from_string(btdc.require<std::string>("s"));
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
        signkey.zero();
        enckey.zero();
        pq.zero();
        derivedSignKey.zero();
        vanity.zero();
    }

    void Identity::regenerate_keys()
    {
        crypto::identity_keygen(signkey);
        crypto::encryption_keygen(enckey);

        pub.update(seckey_to_pubkey(signkey), seckey_to_pubkey(enckey));

        crypto::pqe_keygen(pq);

        if (not crypto::derive_subkey_private(derivedSignKey, signkey, 1))
        {
            throw std::runtime_error("failed to derive subkey");
        }
    }

    bool Identity::KeyExchange(
        path_dh_func dh, SharedSecret& result, const ServiceInfo& other, const KeyExchangeNonce& N) const
    {
        return dh(result, other.encryption_pubkey(), enckey, N);
    }

    bool Identity::Sign(Signature& sig, uint8_t* buf, size_t size) const
    {
        return crypto::sign(sig, signkey, buf, size);
    }

    void Identity::ensure_keys(fs::path fname, bool needBackup)
    {
        // make sure we are empty
        Clear();

        std::string buf;

        // this can throw
        bool exists = fs::exists(fname);

        if (exists and needBackup)
        {
            KeyManager::copy_backup_keyfile(fname);
            exists = false;
        }

        // check for file
        if (!exists)
        {
            // regen and encode
            regenerate_keys();

            buf = bt_encode();

            // write
            try
            {
                llarp::util::buffer_to_file(fname, buf.data(), buf.size());
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error{fmt::format("failed to write {}: {}", fname, e.what())};
            }
            return;
        }

        if (not fs::is_regular_file(fname))
        {
            throw std::invalid_argument{fmt::format("{} is not a regular file", fname)};
        }

        // read file
        try
        {
            llarp::util::file_to_buffer(fname, buf.data(), buf.size());
        }
        catch (const std::length_error&)
        {
            throw std::length_error{"service identity too big"};
        }

        // (don't catch io error exceptions)
        bt_decode(buf);

        // ensure that the encryption key is set
        if (enckey.is_zero())
            crypto::encryption_keygen(enckey);

        // also ensure the ntru key is set
        if (pq.is_zero())
            crypto::pqe_keygen(pq);

        std::optional<VanityNonce> van;
        if (!vanity.is_zero())
            van = vanity;
        // update pubkeys
        pub.update(seckey_to_pubkey(signkey), seckey_to_pubkey(enckey), van);
        if (not crypto::derive_subkey_private(derivedSignKey, signkey, 1))
        {
            throw std::runtime_error("failed to derive subkey");
        }
    }

    std::optional<EncryptedIntroSet> Identity::encrypt_and_sign_introset(
        const IntroSet& other_i, std::chrono::milliseconds now) const
    {
        EncryptedIntroSet encrypted;

        if (other_i.intros.empty())
            return std::nullopt;

        IntroSet i{other_i};
        encrypted.nonce.Randomize();
        // set timestamp
        // TODO: round to nearest 1000 ms
        i.time_signed = now;
        encrypted.signed_at = now;
        // set service info
        i.address_keys = pub;
        // set public encryption key
        i.sntru_pubkey = pq_keypair_to_pubkey(pq);

        auto bte = i.bt_encode();

        const SharedSecret k{i.address_keys.address()};
        crypto::xchacha20(reinterpret_cast<uint8_t*>(bte.data()), bte.size(), k, encrypted.nonce);

        std::memcpy(encrypted.introset_payload.data(), bte.data(), bte.size());

        if (not encrypted.Sign(derivedSignKey))
            return std::nullopt;
        return encrypted;
    }
}  // namespace llarp::service
