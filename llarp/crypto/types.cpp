#include "types.hpp"

#include <llarp/address/keys.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/file.hpp>

#include <oxenc/hex.h>
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
        Ed25519Hash key = to_edhash();
        PubKey pubkey = key.to_pubkey();
        std::memcpy(data() + 32, pubkey.data(), 32);
        return true;
    }

    Ed25519Hash Ed25519SecretKey::to_edhash() const
    {
        Ed25519Hash k;
        unsigned char h[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(h, data(), 32);
        h[0] &= 248;
        h[31] &= 63;
        h[31] |= 64;
        std::memcpy(k.data(), h, 64);
        return k;
    }

    PubKey Ed25519Hash::to_pubkey() const
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
