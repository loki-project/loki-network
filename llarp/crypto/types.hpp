#pragma once

#include "constants.hpp"

#include <llarp/constants/files.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/buffer.hpp>

#include <algorithm>
#include <iostream>

namespace llarp
{
    using SharedSecret = AlignedBuffer<SHAREDKEYSIZE>;
    using KeyExchangeNonce = AlignedBuffer<32>;

    struct PubKey;
    struct Ed25519Hash;

    /// Stores a sodium "secret key" value, which is actually the seed
    /// concatenated with the public key.  Note that the seed is *not* the private
    /// key value itself, but rather the seed from which it can be calculated.
    struct Ed25519SecretKey final : public AlignedBuffer<SECKEYSIZE>
    {
        Ed25519SecretKey() = default;

        explicit Ed25519SecretKey(const uint8_t* ptr) : AlignedBuffer<SECKEYSIZE>(ptr) {}

        // The full data
        explicit Ed25519SecretKey(const AlignedBuffer<SECKEYSIZE>& seed) : AlignedBuffer<SECKEYSIZE>(seed) {}

        // Just the seed, we recalculate the pubkey
        explicit Ed25519SecretKey(const AlignedBuffer<32>& seed)
        {
            std::copy(seed.begin(), seed.end(), begin());
            recalculate();
        }

        /// recalculate public component
        bool recalculate();

        std::string_view to_string() const { return "[secretkey]"; }

        PubKey to_pubkey() const;

        Ed25519Hash to_edhash() const;

        bool load_from_file(const fs::path& fname);

        bool write_to_file(const fs::path& fname) const;
    };

    /// PrivateKey is similar to SecretKey except that it only stores the private
    /// key value and a hash, unlike SecretKey which stores the seed from which
    /// the private key and hash value are generated.  This is primarily intended
    /// for use with derived keys, where we can derive the private key but not the
    /// seed.
    struct Ed25519Hash final : public AlignedBuffer<64>
    {
        Ed25519Hash() = default;

        explicit Ed25519Hash(const uint8_t* ptr) : AlignedBuffer<64>(ptr) {}

        explicit Ed25519Hash(const AlignedBuffer<64>& key_and_hash) : AlignedBuffer<64>(key_and_hash) {}

        // Returns writeable access to the 32-byte Ed25519 Private Scalar
        uspan scalar() { return {data(), 32}; }
        // Returns readable access to the 32-byte Ed25519 Private Scalar
        ustring_view scalar() const { return {data(), 32}; }
        // Returns writeable access to the 32-byte Ed25519 Signing Hash
        uspan signing_hash() { return {data() + 32, 32}; }
        // Returns readable access to the 32-byte Ed25519 Signing Hash
        ustring_view signing_hash() const { return {data() + 32, 32}; }

        std::string_view to_string() const { return "[privatekey]"; }

        PubKey to_pubkey() const;
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
    using path_dh_func = bool (*)(SharedSecret&, const PubKey&, const Ed25519SecretKey&, const TunnelNonce&);
}  // namespace llarp
