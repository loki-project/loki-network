#pragma once

#include "constants.hpp"

#include <llarp/constants/files.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/buffer.hpp>

#include <algorithm>

namespace llarp
{
    using SharedSecret = AlignedBuffer<SHAREDKEYSIZE>;

    struct PubKey;
    struct Ed25519PrivateData;

    /// Stores a sodium "secret key" value, which is actually the Ed25519 seed
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

        PubKey to_pubkey() const;

        Ed25519PrivateData to_eddata() const;

        Ed25519PrivateData derive_private_subkey_data(uint64_t domain = 1) const;

        bool load_from_file(const fs::path& fname);

        bool write_to_file(const fs::path& fname) const;

        std::string_view to_string() const { return "[secretkey]"; }
        static constexpr bool to_string_formattable{true};
    };

    /// Ed25519PrivateData is similar to Ed25519SecretKey except that it only stores the
    /// private scalar and a hash, unlike SecretKey which stores the seed from which
    /// the private key and hash value are generated.
    struct Ed25519PrivateData final : public AlignedBuffer<64>
    {
        friend struct Ed25519SecretKey;

        Ed25519PrivateData() = default;

        explicit Ed25519PrivateData(const uint8_t* ptr) : AlignedBuffer<64>(ptr) {}

        explicit Ed25519PrivateData(const AlignedBuffer<64>& key_and_hash) : AlignedBuffer<64>(key_and_hash) {}

        // Returns writeable access to the 32-byte Ed25519 Private Scalar
        uspan scalar() { return {data(), 32}; }
        // Returns readable access to the 32-byte Ed25519 Private Scalar
        const_uspan scalar() const { return {data(), 32}; }
        // Returns writeable access to the 32-byte Ed25519 Signing Hash
        uspan signing_hash() { return {data() + 32, 32}; }
        // Returns readable access to the 32-byte Ed25519 Signing Hash
        const_uspan signing_hash() const { return {data() + 32, 32}; }

        PubKey to_pubkey() const;

        std::string_view to_string() const { return "[privatekey]"; }
        static constexpr bool to_string_formattable{true};
    };

    using ShortHash = AlignedBuffer<SHORTHASHSIZE>;

    struct Signature final : public AlignedBuffer<SIGSIZE>
    {};

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

}  // namespace llarp
