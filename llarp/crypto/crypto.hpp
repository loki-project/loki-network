#pragma once

#include "types.hpp"

#include <llarp/router_id.hpp>
#include <llarp/util/buffer.hpp>

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
        bool hmac(uint8_t*, uint8_t*, size_t, const SharedSecret&);

        /// ed25519 sign
        bool sign(Signature&, const Ed25519SecretKey&, uint8_t* buf, size_t size);

        /// ed25519 sign, using pointers
        bool sign(uint8_t* sig, uint8_t* sk, uint8_t* buf, size_t size);
        bool sign(uint8_t* sig, const Ed25519SecretKey& sk, ustring_view buf);

        /// ed25519 sign (custom with derived keys)
        bool sign(Signature&, const Ed25519Hash&, uint8_t* buf, size_t size);

        /// ed25519 verify
        bool verify(const PubKey&, ustring_view, ustring_view);
        bool verify(const PubKey&, uint8_t*, size_t, const Signature&);
        bool verify(ustring_view, ustring_view, ustring_view);
        bool verify(uint8_t*, uint8_t*, size_t, uint8_t*);

        /// Used in path-build and session initiation messages. Derives a shared secret key for symmetric DH, encrypting
        /// the given payload in-place. Will throw on failure of either the client DH derivation or the xchacha20
        /// payload mutation
        void derive_encrypt_outer_wrapping(
            const Ed25519SecretKey& shared_key,
            SharedSecret& secret,
            const SymmNonce& nonce,
            const RouterID& remote,
            uspan payload);

        /// Used in receiving path-build and session initiation messages. Derives a shared secret key using an ephemeral
        /// pubkey and the provided nonce. The encrypted payload is mutated in-place. Will throw on failure of either
        /// the server DH derivation or the xchacha20 payload mutation
        void derive_decrypt_outer_wrapping(
            const Ed25519SecretKey& local, const PubKey& remote, const SymmNonce& nonce, uspan encrypted);

        /// derive sub keys for public keys.  hash is really only intended for
        /// testing ands key_n if given.
        bool derive_subkey(
            PubKey& derived, const PubKey& root, uint64_t key_n, const AlignedBuffer<32>* hash = nullptr);

        /// derive sub keys for private keys.  hash is really only intended for
        /// testing ands key_n if given.
        bool derive_subkey_private(
            Ed25519Hash& derived,
            const Ed25519SecretKey& root,
            uint64_t key_n,
            const AlignedBuffer<32>* hash = nullptr);

        /// randomize buffer
        void randomize(uint8_t* buf, size_t len);

        /// randomizer memory
        void randbytes(uint8_t*, size_t);

        /// generate signing keypair
        void identity_keygen(Ed25519SecretKey&);

        /// generate encryption keypair
        void encryption_keygen(Ed25519SecretKey&);

        /// generate post quantum encrytion key
        void pqe_keygen(PQKeyPair&);

        /// post quantum decrypt (buffer, sharedkey_dst, sec)
        bool pqe_decrypt(const PQCipherBlock&, SharedSecret&, const uint8_t*);

        /// post quantum encrypt (buffer, sharedkey_dst,  pub)
        bool pqe_encrypt(PQCipherBlock&, SharedSecret&, const PQPubKey&);

        bool check_identity_privkey(const Ed25519SecretKey&);

        bool check_passwd_hash(std::string pwhash, std::string challenge);
    };  // namespace crypto

    /// return random 64bit unsigned interger
    uint64_t randint();

    const uint8_t* seckey_to_pubkey(const Ed25519SecretKey& secret);

    const uint8_t* pq_keypair_to_pubkey(const PQKeyPair& keypair);

    const uint8_t* pq_keypair_to_seckey(const PQKeyPair& keypair);

    /// rng type that uses llarp::randint(), which is cryptographically secure
    struct CSRNG
    {
        using result_type = uint64_t;

        static constexpr uint64_t min() { return std::numeric_limits<uint64_t>::min(); }

        static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); }

        uint64_t operator()() { return llarp::randint(); }
    };

    extern CSRNG csrng;

}  // namespace llarp
