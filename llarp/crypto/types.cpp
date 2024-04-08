#include "types.hpp"

#include <llarp/address/keys.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/file.hpp>

#include <oxenc/hex.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_scalarmult_ed25519.h>

namespace llarp
{
    // bool PubKey::from_hex(const std::string& str)
    // {
    //     if (str.size() != 2 * size())
    //         return false;
    //     oxenc::from_hex(str.begin(), str.end(), begin());
    //     return true;
    // }

    // PubKey PubKey::make_from_hex(const std::string& s)
    // {
    //     PubKey p;
    //     oxenc::from_hex(s.begin(), s.end(), p.begin());
    //     return p;
    // }

    // std::string PubKey::to_string() const
    // {
    //     return oxenc::to_hex(begin(), end());
    // }

    // PubKey& PubKey::operator=(const uint8_t* ptr)
    // {
    //     std::copy(ptr, ptr + SIZE, begin());
    //     return *this;
    // }

    // bool operator==(const PubKey& lhs, const PubKey& rhs)
    // {
    //     return lhs.as_array() == rhs.as_array();
    // }

    PubKey SecretKey::to_pubkey() const
    {
        return PubKey(data() + 32);
    }

    bool SecretKey::load_from_file(const fs::path& fname)
    {
        size_t sz;
        std::array<uint8_t, 128> tmp;
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

        llarp_buffer_t buf(tmp);
        return BDecode(&buf);
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
