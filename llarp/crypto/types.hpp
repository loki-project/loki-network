#pragma once

#include "constants.hpp"

#include <llarp/util/aligned.hpp>
#include <llarp/util/fs.hpp>
#include <llarp/util/types.hpp>

#include <algorithm>
#include <iostream>

namespace llarp
{
    using SharedSecret = AlignedBuffer<SHAREDKEYSIZE>;
    using KeyExchangeNonce = AlignedBuffer<32>;

    // struct RouterID;

    struct PubKey : public AlignedBuffer<PUBKEYSIZE>
    {
        PubKey() = default;

        explicit PubKey(const uint8_t* ptr) : AlignedBuffer<SIZE>(ptr)
        {}

        explicit PubKey(const std::array<uint8_t, SIZE>& data) : AlignedBuffer<SIZE>(data)
        {}

        explicit PubKey(const AlignedBuffer<SIZE>& other) : AlignedBuffer<SIZE>(other)
        {}

        std::string to_string() const;

        bool from_hex(const std::string& str);

        static PubKey make_from_hex(const std::string& s);

        PubKey& operator=(const uint8_t* ptr);
    };

    bool operator==(const PubKey& lhs, const PubKey& rhs);

    struct PrivateKey;

    /// Stores a sodium "secret key" value, which is actually the seed
    /// concatenated with the public key.  Note that the seed is *not* the private
    /// key value itself, but rather the seed from which it can be calculated.
    struct SecretKey final : public AlignedBuffer<SECKEYSIZE>
    {
        SecretKey() = default;

        explicit SecretKey(const uint8_t* ptr) : AlignedBuffer<SECKEYSIZE>(ptr)
        {}

        // The full data
        explicit SecretKey(const AlignedBuffer<SECKEYSIZE>& seed) : AlignedBuffer<SECKEYSIZE>(seed)
        {}

        // Just the seed, we recalculate the pubkey
        explicit SecretKey(const AlignedBuffer<32>& seed)
        {
            std::copy(seed.begin(), seed.end(), begin());
            Recalculate();
        }

        /// recalculate public component
        bool Recalculate();

        std::string_view to_string() const
        {
            return "[secretkey]";
        }

        PubKey to_pubkey() const
        {
            return PubKey(data() + 32);
        }

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

        explicit PrivateKey(const uint8_t* ptr) : AlignedBuffer<64>(ptr)
        {}

        explicit PrivateKey(const AlignedBuffer<64>& key_and_hash) : AlignedBuffer<64>(key_and_hash)
        {}

        /// Returns a pointer to the beginning of the 32-byte hash which is used for
        /// pseudorandomness when signing with this private key.
        const uint8_t* signing_hash() const
        {
            return data() + 32;
        }

        /// Returns a pointer to the beginning of the 32-byte hash which is used for
        /// pseudorandomness when signing with this private key.
        uint8_t* signing_hash()
        {
            return data() + 32;
        }

        std::string_view to_string() const
        {
            return "[privatekey]";
        }

        /// Computes the public key
        bool to_pubkey(PubKey& pubkey) const;
    };

    template <>
    constexpr inline bool IsToStringFormattable<PubKey> = true;
    template <>
    constexpr inline bool IsToStringFormattable<SecretKey> = true;
    template <>
    constexpr inline bool IsToStringFormattable<PrivateKey> = true;

    using ShortHash = AlignedBuffer<SHORTHASHSIZE>;
    using LongHash = AlignedBuffer<HASHSIZE>;

    struct Signature final : public AlignedBuffer<SIGSIZE>
    {
        //
    };

    using TunnelNonce = AlignedBuffer<TUNNONCESIZE>;
    using SymmNonce = AlignedBuffer<NONCESIZE>;
    using SymmKey = AlignedBuffer<32>;  // not used

    using PQCipherBlock = AlignedBuffer<PQ_CIPHERTEXTSIZE + 1>;
    using PQPubKey = AlignedBuffer<PQ_PUBKEYSIZE>;
    using PQKeyPair = AlignedBuffer<PQ_KEYPAIRSIZE>;

    /// PKE(result, publickey, secretkey, nonce)
    using path_dh_func = bool (*)(SharedSecret&, const PubKey&, const SecretKey&, const TunnelNonce&);

    /// SH(result, body)
    using shorthash_func = bool (*)(ShortHash&, const llarp_buffer_t&);
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::PubKey> : hash<llarp::AlignedBuffer<llarp::PubKey::SIZE>>
    {};
};  // namespace std
