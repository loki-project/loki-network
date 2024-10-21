#include "types.hpp"

#include <llarp/address/keys.hpp>
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

    PubKey Ed25519SecretKey::to_pubkey() const
    {
        return PubKey(data() + 32);
    }

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

        AlignedBuffer<32> h;

        if (not crypto::make_scalar(h, to_pubkey(), domain))
            throw std::runtime_error{"Call to `make_scalar` failed in deriving private subkey!"};

        h[0] &= 248;
        h[31] &= 63;
        h[31] |= 64;

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

}  // namespace llarp
