#include "types.hpp"

#include <llarp/contact/router_id.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/file.hpp>

#include <oxenc/hex.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_scalarmult_ed25519.h>

namespace llarp
{
    static auto logcat = log::Cat("cryptoutils");

    PubKey Ed25519SecretKey::to_pubkey() const { return PubKey(data() + 32); }

    bool Ed25519SecretKey::load_from_file(const fs::path& fname)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        size_t sz;
        std::string tmp;
        tmp.resize(128);

        try
        {
            sz = util::file_to_buffer(fname, tmp.data(), tmp.size());
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "Failed to read contents from file: {}", e.what());
            return false;
        }

        std::copy_n(tmp.begin(), sz, begin());
        return true;
    }

    bool Ed25519SecretKey::recalculate()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        Ed25519PrivateData key = to_eddata();
        PubKey pubkey = key.to_pubkey();
        std::memcpy(data() + 32, pubkey.data(), 32);
        return true;
    }

    Ed25519PrivateData Ed25519SecretKey::to_eddata() const
    {
        Ed25519PrivateData k;
        unsigned char h[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(h, data(), 32);
        h[0] &= 248;
        h[31] &= 63;
        h[31] |= 64;
        std::memcpy(k.data(), h, 64);
        return k;
    }

    Ed25519PrivateData Ed25519SecretKey::derive_private_subkey_data(uint64_t domain) const
    {
        Ed25519PrivateData ret{};

        std::array<unsigned char, 32> h = crypto::make_scalar(to_pubkey(), domain);

        auto a = to_eddata();

        // a' = ha
        crypto_core_ed25519_scalar_mul(ret.data(), h.data(), a.data());

        // s' = H(h || s)
        std::array<uint8_t, 64> buf;
        std::copy(h.begin(), h.end(), buf.begin());
        std::copy(a.signing_hash().begin(), a.signing_hash().end(), buf.begin() + 32);
        if (crypto_generichash_blake2b(ret.signing_hash().data(), 32, buf.data(), buf.size(), nullptr, 0) == -1)
            throw std::runtime_error{"Call to `crypto_generichash_blake2b` failed!"};
        return ret;
    }

    PubKey Ed25519PrivateData::to_pubkey() const
    {
        PubKey p;
        crypto_scalarmult_ed25519_base_noclamp(p.data(), data());
        return p;
    }

    bool Ed25519SecretKey::write_to_file(const fs::path& fname) const
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        try
        {
            util::buffer_to_file(fname, to_view());
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "Failed to write contents to file: {}", e.what());
            return false;
        }

        return true;
    }

    SymmNonce SymmNonce::make(std::string nonce)
    {
        SymmNonce n;
        if (!n.from_string(nonce))
            throw std::invalid_argument{"Invalid nonce passed to static constructor function:{}"_format(nonce)};
        return n;
    }

    SymmNonce SymmNonce::make_random()
    {
        SymmNonce n;
        n.Randomize();
        return n;
    }

    shared_kx_data::shared_kx_data(Ed25519SecretKey&& sk) : ephemeral_key{std::move(sk)}
    {
        pubkey = ephemeral_key.to_pubkey();
    }

    void shared_kx_data::generate_xor()
    {
        ShortHash xhash;
        crypto::shorthash(xhash, shared_secret.data(), shared_secret.size());
        xor_nonce = xhash.data();  // truncate 32 -> 24
    }

    shared_kx_data shared_kx_data::generate() { return shared_kx_data{crypto::generate_identity()}; }

    // TESTNET: TODO: check if the libsodium functions ever actually fail...

    void shared_kx_data::client_dh(const RouterID& remote)
    {
        if (!crypto::dh_client(shared_secret, remote, ephemeral_key, nonce))
            throw std::runtime_error{"Client DH failed -- should this even ever happen?"};
    }

    void shared_kx_data::server_dh(const Ed25519SecretKey& local_sk)
    {
        if (!crypto::dh_server(shared_secret, pubkey, local_sk, nonce))
            throw std::runtime_error{"Server DH failed -- should this even ever happen?"};
    }

    void shared_kx_data::encrypt(std::span<uint8_t> data)
    {
        if (!crypto::xchacha20(data.data(), data.size(), shared_secret, nonce))
            throw std::runtime_error{"xchacha20 encryption failed -- should this even ever happen?"};
    }

    // identical methods, separated for clarity of use/logging for now
    void shared_kx_data::decrypt(std::span<uint8_t> data)
    {
        if (!crypto::xchacha20(data.data(), data.size(), shared_secret, nonce))
            throw std::runtime_error{"xchacha20 decryption failed -- should this even ever happen?"};
    }

}  // namespace llarp
