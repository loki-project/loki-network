#pragma once

#include "types.hpp"

#include <llarp/contact/router_id.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/random.hpp>

#include <cstdint>

namespace llarp
{
    /*
        TODO:
          - make uint8_t pointers const where needed
    */

    namespace crypto
    {
        /// decrypt cipherText given the key generated from name
        std::optional<AlignedBuffer<32>> maybe_decrypt_name(
            std::string_view ciphertext, SymmNonce nonce, std::string_view name);

        /// xchacha symmetric cipher
        bool xchacha20(uint8_t* buf, size_t size, const SharedSecret&, const SymmNonce&);
        bool xchacha20(uint8_t* buf, size_t size, const uint8_t* secret, const uint8_t* nonce);

        SymmNonce onion(
            unsigned char* buf,
            size_t size,
            const SharedSecret& k,
            const SymmNonce& nonce,
            const SymmNonce& xor_factor);

        /// path dh creator's side
        bool dh_client(SharedSecret&, const PubKey&, const Ed25519SecretKey&, const SymmNonce&);

        /// path dh relay side
        bool dh_server(SharedSecret&, const PubKey&, const Ed25519SecretKey&, const SymmNonce&);
        bool dh_server(uint8_t* shared_secret, const uint8_t* other_pk, const uint8_t* local_sk, const uint8_t* nonce);

        /// blake2b 256 bit
        bool shorthash(ShortHash&, uint8_t*, size_t size);

        /// blake2s 256 bit hmac
        bool hmac(uint8_t*, const uint8_t*, size_t, const SharedSecret&);

        /// ed25519 sign
        bool sign(Signature&, const Ed25519SecretKey&, uint8_t* buf, size_t size);

        /// ed25519 sign, using pointers
        bool sign(uint8_t* sig, uint8_t* sk, uint8_t* buf, size_t size);
        bool sign(uint8_t* sig, const Ed25519SecretKey& sk, ustring_view buf);

        /// ed25519 sign (custom with derived keys)
        bool sign(Signature&, const Ed25519PrivateData&, const uint8_t* buf, size_t size);

        /// ed25519 verify
        bool verify(const PubKey&, ustring_view, ustring_view);
        bool verify(const PubKey&, const uint8_t*, size_t, const Signature&);
        bool verify(ustring_view, ustring_view, ustring_view);

        /// Used in path-build and session initiation messages. Derives a shared secret key for symmetric DH, encrypting
        /// the given payload in-place. Will throw on failure of either the client DH derivation or the xchacha20
        /// payload mutation
        void derive_encrypt_outer_wrapping(
            const Ed25519SecretKey& shared_key,
            SharedSecret& secret,
            const SymmNonce& nonce,
            const RouterID& remote,
            std::span<uint8_t> payload);

        // void derive_encrypt_outer_wrapping(
        //     const Ed25519SecretKey& shared_key,
        //     SharedSecret& secret,
        //     const SymmNonce& nonce,
        //     const RouterID& remote,
        //     uspan payload);

        /// Used in receiving path-build and session initiation messages. Derives a shared secret key using an ephemeral
        /// pubkey and the provided nonce. The encrypted payload is mutated in-place. Will throw on failure of either
        /// the server DH derivation or the xchacha20 payload mutation
        void derive_decrypt_outer_wrapping(
            const Ed25519SecretKey& local,
            SharedSecret& shared,
            const PubKey& remote,
            const SymmNonce& nonce,
            std::span<uint8_t> encrypted);

        std::array<unsigned char, 32> make_scalar(const PubKey& k, uint64_t domain);

        /// derive sub keys for public keys.  hash is really only intended for
        /// testing ands key_n if given.
        bool derive_subkey(uint8_t* derived, size_t derived_len, const PubKey& root, uint64_t key_n);

        /// randomize buffer
        void randomize(uint8_t* buf, size_t len);

        /// randomizer memory
        void randbytes(uint8_t*, size_t);

        Ed25519SecretKey generate_identity();

        bool check_identity_privkey(const Ed25519SecretKey&);

        bool check_passwd_hash(std::string pwhash, std::string challenge);
    };  // namespace crypto

    /// return random 64bit unsigned interger
    uint64_t randint();

    const uint8_t* seckey_to_pubkey(const Ed25519SecretKey& secret);

    /// rng type that uses llarp::randint(), which is cryptographically secure

}  // namespace llarp
