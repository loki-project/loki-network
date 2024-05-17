#pragma once

#include "constants.hpp"

#include <llarp/constants/files.hpp>
#include <llarp/util/aligned.hpp>

#include <algorithm>
#include <iostream>

namespace llarp
{
    using SharedSecret = AlignedBuffer<SHAREDKEYSIZE>;
    using KeyExchangeNonce = AlignedBuffer<32>;

    struct PubKey;
    struct PrivateKey;

    /// Stores a sodium "secret key" value, which is actually the seed
    /// concatenated with the public key.  Note that the seed is *not* the private
    /// key value itself, but rather the seed from which it can be calculated.
    struct SecretKey final : public AlignedBuffer<SECKEYSIZE>
    {
        SecretKey() = default;

        explicit SecretKey(const uint8_t* ptr) : AlignedBuffer<SECKEYSIZE>(ptr) {}

        // The full data
        explicit SecretKey(const AlignedBuffer<SECKEYSIZE>& seed) : AlignedBuffer<SECKEYSIZE>(seed) {}

        // Just the seed, we recalculate the pubkey
        explicit SecretKey(const AlignedBuffer<32>& seed)
        {
            std::copy(seed.begin(), seed.end(), begin());
            recalculate();
        }

        /// recalculate public component
        bool recalculate();

        std::string_view to_string() const { return "[secretkey]"; }

        PubKey to_pubkey() const;

        /// Computes the private key from the secret key (which is actually the
        /// seed)
        bool to_privkey(PrivateKey& key) const;

        bool load_from_file(const fs::path& fname);

        bool write_to_file(const fs::path& fname) const;
    };

    /// PrivateKey is similar to SecretKey except that it only stores the private
    /// key value and a hash, unlike SecretKey which stores the seed from which
    /// the private key and hash value are generated.  This is primarily intended
    /// for use with derived keys, where we can derive the private key but not the
    /// seed.
    struct PrivateKey final : public AlignedBuffer<64>
    {
        PrivateKey() = default;

        explicit PrivateKey(const uint8_t* ptr) : AlignedBuffer<64>(ptr) {}

        explicit PrivateKey(const AlignedBuffer<64>& key_and_hash) : AlignedBuffer<64>(key_and_hash) {}

        /// Returns a pointer to the beginning of the 32-byte hash which is used for
        /// pseudorandomness when signing with this private key.
        const uint8_t* signing_hash() const { return data() + 32; }

        /// Returns a pointer to the beginning of the 32-byte hash which is used for
        /// pseudorandomness when signing with this private key.
        uint8_t* signing_hash() { return data() + 32; }

        std::string_view to_string() const { return "[privatekey]"; }

        /// Computes the public key
        bool to_pubkey(PubKey& pubkey) const;
    };

    using ShortHash = AlignedBuffer<SHORTHASHSIZE>;
    using LongHash = AlignedBuffer<HASHSIZE>;

    struct Signature final : public AlignedBuffer<SIGSIZE>
    {};

    // using SymmNonce = AlignedBuffer<NONCESIZE>;

    struct SymmNonce final : public AlignedBuffer<NONCESIZE>
    {
        using AlignedBuffer<NONCESIZE>::AlignedBuffer;

        SymmNonce operator^(const SymmNonce& other) const
        {
            SymmNonce ret;
            std::transform(begin(), end(), other.begin(), ret.begin(), std::bit_xor<>());
            return ret;
        }

        static SymmNonce make(std::string n);

        static SymmNonce make_random();
    };

    using TunnelNonce = AlignedBuffer<TUNNONCESIZE>;
    using SymmKey = AlignedBuffer<32>;  // not used

    using PQCipherBlock = AlignedBuffer<PQ_CIPHERTEXTSIZE + 1>;
    using PQPubKey = AlignedBuffer<PQ_PUBKEYSIZE>;
    using PQKeyPair = AlignedBuffer<PQ_KEYPAIRSIZE>;

    /// PKE(result, publickey, secretkey, nonce)
    using path_dh_func = bool (*)(SharedSecret&, const PubKey&, const SecretKey&, const TunnelNonce&);
}  // namespace llarp
