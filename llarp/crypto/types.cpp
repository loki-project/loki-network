#include "types.hpp"

#include <llarp/address/keys.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/file.hpp>

#include <oxenc/hex.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_scalarmult_ed25519.h>

namespace llarp
{
    PubKey SecretKey::to_pubkey() const
    {
        return PubKey(data() + 32);
    }

    bool SecretKey::load_from_file(const fs::path& fname)
    {
        size_t sz;
        std::string tmp;
        tmp.resize(128);

        try
        {
            sz = util::file_to_buffer(fname, tmp.data(), tmp.size());
        }
        catch (const std::exception&)
        {
            return false;
        }

        if (sz == size())
        {
            // is raw buffer
            std::copy_n(tmp.begin(), sz, begin());
            return true;
        }

        oxenc::bt_deserialize(tmp, *data());
        // return true;
        return bt_decode(tmp);
    }

    bool SecretKey::recalculate()
    {
        PrivateKey key;
        PubKey pubkey;
        if (!to_privkey(key) || !key.to_pubkey(pubkey))
            return false;
        std::memcpy(data() + 32, pubkey.data(), 32);
        return true;
    }

    bool SecretKey::to_privkey(PrivateKey& key) const
    {
        // Ed25519 calculates a 512-bit hash from the seed; the first half (clamped)
        // is the private key; the second half is the hash that gets used in
        // signing.
        unsigned char h[crypto_hash_sha512_BYTES];
        if (crypto_hash_sha512(h, data(), 32) < 0)
            return false;
        h[0] &= 248;
        h[31] &= 63;
        h[31] |= 64;
        std::memcpy(key.data(), h, 64);
        return true;
    }

    bool PrivateKey::to_pubkey(PubKey& pubkey) const
    {
        return crypto_scalarmult_ed25519_base_noclamp(pubkey.data(), data()) != -1;
    }

    bool SecretKey::write_to_file(const fs::path& fname) const
    {
        auto bte = bt_encode();

        try
        {
            util::buffer_to_file(fname, bte);
        }
        catch (const std::exception& e)
        {
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
