#include "crypto.hpp"

#include <oxenc/endian.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_stream_xchacha20.h>
#include <sodium/utils.h>

#include <cassert>
#include <cstring>
#ifdef HAVE_CRYPT
#include <crypt.h>
#endif

namespace llarp
{
    static auto logcat = log::Cat("crypto");

    static bool dh(
        llarp::SharedSecret& out,
        const PubKey& client_pk,
        const PubKey& server_pk,
        const uint8_t* themPub,
        const SecretKey& usSec)
    {
        llarp::SharedSecret shared;
        crypto_generichash_state h;

        if (crypto_scalarmult_curve25519(shared.data(), usSec.data(), themPub))
        {
            return false;
        }
        crypto_generichash_blake2b_init(&h, nullptr, 0U, shared.size());
        crypto_generichash_blake2b_update(&h, client_pk.data(), 32);
        crypto_generichash_blake2b_update(&h, server_pk.data(), 32);
        crypto_generichash_blake2b_update(&h, shared.data(), 32);
        crypto_generichash_blake2b_final(&h, out.data(), shared.size());
        return true;
    }

    static bool dh(
        uint8_t* out, const uint8_t* client_pk, const uint8_t* server_pk, const uint8_t* themPub, const uint8_t* usSec)
    {
        llarp::SharedSecret shared;
        crypto_generichash_state h;

        if (crypto_scalarmult_curve25519(shared.data(), usSec, themPub))
        {
            return false;
        }
        crypto_generichash_blake2b_init(&h, nullptr, 0U, shared.size());
        crypto_generichash_blake2b_update(&h, client_pk, 32);
        crypto_generichash_blake2b_update(&h, server_pk, 32);
        crypto_generichash_blake2b_update(&h, shared.data(), 32);
        crypto_generichash_blake2b_final(&h, out, shared.size());
        return true;
    }

    static bool dh_client_priv(llarp::SharedSecret& shared, const PubKey& pk, const SecretKey& sk, const SymmNonce& n)
    {
        llarp::SharedSecret dh_result;

        if (dh(dh_result, sk.to_pubkey(), pk, pk.data(), sk))
        {
            return crypto_generichash_blake2b(shared.data(), 32, n.data(), 32, dh_result.data(), 32) != -1;
        }

        log::warning(logcat, "crypto::dh_client - dh failed");
        return false;
    }

    static bool dh_server_priv(llarp::SharedSecret& shared, const PubKey& pk, const SecretKey& sk, const SymmNonce& n)
    {
        llarp::SharedSecret dh_result;

        if (dh(dh_result, pk, sk.to_pubkey(), pk.data(), sk))
        {
            return crypto_generichash_blake2b(shared.data(), 32, n.data(), n.size(), dh_result.data(), 32) != -1;
        }

        log::warning(logcat, "crypto::dh_server - dh failed");
        return false;
    }

    static bool dh_server_priv(uint8_t* shared, const uint8_t* pk, const uint8_t* sk, const uint8_t* nonce)
    {
        llarp::SharedSecret dh_result;

        if (dh(dh_result.data(), pk, sk, pk, sk))
        {
            return crypto_generichash_blake2b(shared, 32, nonce, 24, dh_result.data(), 32) != -1;
        }

        log::warning(logcat, "crypto::dh_server - dh failed");
        return false;
    }

    std::optional<AlignedBuffer<32>> crypto::maybe_decrypt_name(
        std::string_view ciphertext, SymmNonce nonce, std::string_view name)
    {
        const auto payloadsize = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        if (payloadsize != 32)
            return {};

        SharedSecret derivedKey{};
        ShortHash namehash{};
        ustring name_buf{reinterpret_cast<const uint8_t*>(name.data()), name.size()};

        if (not shorthash(namehash, name_buf.data(), name_buf.size()))
            return {};
        if (not hmac(derivedKey.data(), name_buf.data(), derivedKey.size(), namehash))
            return {};
        AlignedBuffer<32> result{};
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                result.data(),
                nullptr,
                nullptr,
                reinterpret_cast<const uint8_t*>(ciphertext.data()),
                ciphertext.size(),
                nullptr,
                0,
                nonce.data(),
                derivedKey.data())
            == -1)
        {
            return {};
        }
        return result;
    }

    bool crypto::xchacha20(uint8_t* buf, size_t size, const SharedSecret& k, const SymmNonce& n)
    {
        return xchacha20(buf, size, n.data(), k.data());
    }

    bool crypto::xchacha20(uint8_t* buf, size_t size, const uint8_t* secret, const uint8_t* nonce)
    {
        return crypto_stream_xchacha20_xor(buf, buf, size, nonce, secret) == 0;
    }

    // do a round of chacha for and return the nonce xor the given xor_factor
    SymmNonce crypto::onion(
        unsigned char* buf, size_t size, const SharedSecret& k, const SymmNonce& nonce, const SymmNonce& xor_factor)
    {
        if (!crypto::xchacha20(buf, size, k, nonce))
            throw std::runtime_error{"chacha failed during onion step"};

        return nonce ^ xor_factor;
    }

    bool crypto::dh_client(llarp::SharedSecret& shared, const PubKey& pk, const SecretKey& sk, const SymmNonce& n)
    {
        return dh_client_priv(shared, pk, sk, n);
    }
    /// path dh relay side
    bool crypto::dh_server(llarp::SharedSecret& shared, const PubKey& pk, const SecretKey& sk, const SymmNonce& n)
    {
        return dh_server_priv(shared, pk, sk, n);
    }

    bool crypto::dh_server(
        uint8_t* shared_secret, const uint8_t* other_pk, const uint8_t* local_pk, const uint8_t* nonce)
    {
        return dh_server_priv(shared_secret, other_pk, local_pk, nonce);
    }

    bool crypto::shorthash(ShortHash& result, uint8_t* buf, size_t size)
    {
        return crypto_generichash_blake2b(result.data(), ShortHash::SIZE, buf, size, nullptr, 0) != -1;
    }

    bool crypto::hmac(uint8_t* result, uint8_t* buf, size_t size, const SharedSecret& secret)
    {
        return crypto_generichash_blake2b(result, HMACSIZE, buf, size, secret.data(), HMACSECSIZE) != -1;
    }

    static bool hash(uint8_t* result, const llarp_buffer_t& buff)
    {
        return crypto_generichash_blake2b(result, HASHSIZE, buff.base, buff.sz, nullptr, 0) != -1;
    }

    bool crypto::sign(Signature& sig, const SecretKey& secret, uint8_t* buf, size_t size)
    {
        return crypto_sign_detached(sig.data(), nullptr, buf, size, secret.data()) != -1;
    }

    bool crypto::sign(uint8_t* sig, uint8_t* sk, uint8_t* buf, size_t size)
    {
        return crypto_sign_detached(sig, nullptr, buf, size, sk) != -1;
    }

    bool crypto::sign(uint8_t* sig, const SecretKey& sk, ustring_view buf)
    {
        return crypto_sign_detached(sig, nullptr, buf.data(), buf.size(), sk.data()) != -1;
    }

    bool crypto::sign(Signature& sig, const PrivateKey& privkey, uint8_t* buf, size_t size)
    {
        PubKey pubkey;

        privkey.to_pubkey(pubkey);

        crypto_hash_sha512_state hs;
        unsigned char nonce[64];
        unsigned char hram[64];
        unsigned char mulres[32];

        // r = H(s || M) where here s is pseudorandom bytes typically generated as
        // part of hashing the seed (i.e. [a,s] = H(k)), but for derived
        // PrivateKeys will come from a hash of the root key's s concatenated with
        // the derivation hash.
        crypto_hash_sha512_init(&hs);
        crypto_hash_sha512_update(&hs, privkey.signing_hash(), 32);
        crypto_hash_sha512_update(&hs, buf, size);
        crypto_hash_sha512_final(&hs, nonce);
        crypto_core_ed25519_scalar_reduce(nonce, nonce);

        // copy pubkey into sig to make (for now) sig = (R || A)
        memmove(sig.data() + 32, pubkey.data(), 32);

        // R = r * B
        crypto_scalarmult_ed25519_base_noclamp(sig.data(), nonce);

        // hram = H(R || A || M)
        crypto_hash_sha512_init(&hs);
        crypto_hash_sha512_update(&hs, sig.data(), 64);
        crypto_hash_sha512_update(&hs, buf, size);
        crypto_hash_sha512_final(&hs, hram);

        // S = r + H(R || A || M) * s, so sig = (R || S)
        crypto_core_ed25519_scalar_reduce(hram, hram);
        crypto_core_ed25519_scalar_mul(mulres, hram, privkey.data());
        crypto_core_ed25519_scalar_add(sig.data() + 32, mulres, nonce);

        sodium_memzero(nonce, sizeof nonce);

        return true;
    }

    bool crypto::verify(const PubKey& pub, ustring_view data, ustring_view sig)
    {
        return (pub.size() == 32 && sig.size() == 64)
            ? crypto_sign_verify_detached(sig.data(), data.data(), data.size(), pub.data()) != -1
            : false;
    }

    bool crypto::verify(const PubKey& pub, uint8_t* buf, size_t size, const Signature& sig)
    {
        return crypto_sign_verify_detached(sig.data(), buf, size, pub.data()) != -1;
    }

    bool crypto::verify(ustring_view pub, ustring_view buf, ustring_view sig)
    {
        return (pub.size() == 32 && sig.size() == 64)
            ? crypto_sign_verify_detached(sig.data(), buf.data(), buf.size(), pub.data()) != -1
            : false;
    }

    bool crypto::verify(uint8_t* pub, uint8_t* buf, size_t size, uint8_t* sig)
    {
        return crypto_sign_verify_detached(sig, buf, size, pub) != -1;
    }

    /// clamp a 32 byte ec point
    static void clamp_ed25519(uint8_t* out)
    {
        out[0] &= 248;
        out[31] &= 127;
        out[31] |= 64;
    }

    template <typename K>
    static K clamp(const K& p)
    {
        K out = p;
        clamp_ed25519(out);
        return out;
    }

    template <typename K>
    static bool is_clamped(const K& key)
    {
        K other(key);
        clamp_ed25519(other.data());
        return other == key;
    }

    static constexpr char derived_key_hash_str[161] =
        "just imagine what would happen if we all decided to understand. you "
        "can't in the and by be or then before so just face it this text hurts "
        "to read? lokinet yolo!";

    template <typename K>
    static bool make_scalar(AlignedBuffer<32>& out, const K& k, uint64_t i)
    {
        // b = BLIND-STRING || k || i
        std::array<uint8_t, 160 + K::SIZE + sizeof(uint64_t)> buf;
        std::copy(derived_key_hash_str, derived_key_hash_str + 160, buf.begin());
        std::copy(k.begin(), k.end(), buf.begin() + 160);
        oxenc::write_host_as_little(i, buf.data() + 160 + K::SIZE);
        // n = H(b)
        // h = make_point(n)
        ShortHash n;
        return -1 != crypto_generichash_blake2b(n.data(), ShortHash::SIZE, buf.data(), buf.size(), nullptr, 0)
            && -1 != crypto_core_ed25519_from_uniform(out.data(), n.data());
    }

    static AlignedBuffer<32> zero;

    bool crypto::derive_subkey(
        PubKey& out_pubkey, const PubKey& root_pubkey, uint64_t key_n, const AlignedBuffer<32>* hash)
    {
        // scalar h = H( BLIND-STRING || root_pubkey || key_n )
        AlignedBuffer<32> h;
        if (hash)
            h = *hash;
        else if (not make_scalar(h, root_pubkey, key_n))
        {
            log::error(logcat, "cannot make scalar");
            return false;
        }

        return 0 == crypto_scalarmult_ed25519(out_pubkey.data(), h.data(), root_pubkey.data());
    }

    bool crypto::derive_subkey_private(
        PrivateKey& out_key, const SecretKey& root_key, uint64_t key_n, const AlignedBuffer<32>* hash)
    {
        // Derives a private subkey from a root key.
        //
        // The basic idea is:
        //
        // h = H( BLIND-STRING || A || key_n )
        // a - private key
        // A = aB - public key
        // s - signing hash
        // a' = ah - derived private key
        // A' = a'B = (ah)B - derived public key
        // s' = H(h || s) - derived signing hash
        //
        // libsodium throws some wrenches in the mechanics which are a nuisance,
        // the biggest of which is that sodium's secret key is *not* `a`; rather
        // it is the seed.  If you want to get the private key (i.e. "a"), you
        // need to SHA-512 hash it and then clamp that.
        //
        // This also makes signature verification harder: we can't just use
        // sodium's sign function because it wants to be given the seed rather
        // than the private key, and moreover we can't actually *get* the seed to
        // make libsodium happy because we only have `ah` above; thus we
        // reimplemented most of sodium's detached signing function but without
        // the hash step.
        //
        // Lastly, for the signing hash s', we need some value that is both
        // different from the root s but also unknowable from the public key
        // (since otherwise `r` in the signing function would be known), so we
        // generate it from a hash of `h` and the root key's (psuedorandom)
        // signing hash, `s`.
        //
        const auto root_pubkey = root_key.to_pubkey();

        AlignedBuffer<32> h;
        if (hash)
            h = *hash;
        else if (not make_scalar(h, root_pubkey, key_n))
        {
            log::error(logcat, "cannot make scalar");
            return false;
        }

        h[0] &= 248;
        h[31] &= 63;
        h[31] |= 64;

        PrivateKey a;
        if (!root_key.to_privkey(a))
            return false;

        // a' = ha
        crypto_core_ed25519_scalar_mul(out_key.data(), h.data(), a.data());

        // s' = H(h || s)
        std::array<uint8_t, 64> buf;
        std::copy(h.begin(), h.end(), buf.begin());
        std::copy(a.signing_hash(), a.signing_hash() + 32, buf.begin() + 32);
        return -1 != crypto_generichash_blake2b(out_key.signing_hash(), 32, buf.data(), buf.size(), nullptr, 0);

        return true;
    }

    void crypto::randomize(uint8_t* buf, size_t len)
    {
        randombytes(buf, len);
    }

    void crypto::randbytes(uint8_t* ptr, size_t sz)
    {
        randombytes((unsigned char*)ptr, sz);
    }

    void crypto::identity_keygen(llarp::SecretKey& keys)
    {
        PubKey pk;
        int result = crypto_sign_keypair(pk.data(), keys.data());
        assert(result != -1);
        const PubKey sk_pk = keys.to_pubkey();
        assert(pk == sk_pk);
        (void)result;
        (void)sk_pk;

        // encryption_keygen(keys);
    }

    bool crypto::check_identity_privkey(const llarp::SecretKey& keys)
    {
        AlignedBuffer<crypto_sign_SEEDBYTES> seed;
        llarp::PubKey pk;
        llarp::SecretKey sk;
        if (crypto_sign_ed25519_sk_to_seed(seed.data(), keys.data()) == -1)
            return false;
        if (crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data()) == -1)
            return false;
        return keys.to_pubkey() == pk && sk == keys;
    }

    void crypto::encryption_keygen(llarp::SecretKey& keys)
    {
        auto d = keys.data();
        randbytes(d, 32);
        crypto_scalarmult_curve25519_base(d + 32, d);
    }

    bool crypto::pqe_encrypt(PQCipherBlock& ciphertext, SharedSecret& sharedkey, const PQPubKey& pubkey)
    {
        return crypto_kem_enc(ciphertext.data(), sharedkey.data(), pubkey.data()) != -1;
    }
    bool crypto::pqe_decrypt(const PQCipherBlock& ciphertext, SharedSecret& sharedkey, const uint8_t* secretkey)
    {
        return crypto_kem_dec(sharedkey.data(), ciphertext.data(), secretkey) != -1;
    }

    void crypto::pqe_keygen(PQKeyPair& keypair)
    {
        auto d = keypair.data();
        crypto_kem_keypair(d + PQ_SECRETKEYSIZE, d);
    }

#ifdef HAVE_CRYPT
    bool crypto::check_passwd_hash(std::string pwhash, std::string challenge)
    {
        bool ret = false;
        auto pos = pwhash.find_last_of('$');
        auto settings = pwhash.substr(0, pos);
        crypt_data data{};
        if (char* ptr = crypt_r(challenge.c_str(), settings.c_str(), &data))
        {
            ret = ptr == pwhash;
        }
        sodium_memzero(&data, sizeof(data));
        return ret;
    }
#endif

    const uint8_t* seckey_to_pubkey(const SecretKey& sec)
    {
        return sec.data() + 32;
    }

    const uint8_t* pq_keypair_to_pubkey(const PQKeyPair& k)
    {
        return k.data() + PQ_SECRETKEYSIZE;
    }

    const uint8_t* pq_keypair_to_seckey(const PQKeyPair& k)
    {
        return k.data();
    }

    uint64_t randint()
    {
        uint64_t i;
        randombytes((uint8_t*)&i, sizeof(i));
        return i;
    }

    // Called during static initialization to initialize libsodium and ntru.  (The CSRNG return is
    // not useful, but just here to get this called during static initialization of `llarp::csrng`).
    static CSRNG _initialize_crypto()
    {
        if (sodium_init() == -1)
        {
            log::critical(logcat, "sodium_init() failed, unable to continue!");
            std::abort();
        }
        char* avx2 = std::getenv("AVX2_FORCE_DISABLE");
        ntru_init(avx2 && avx2 == "1"sv);

        return CSRNG{};
    }

    CSRNG csrng = _initialize_crypto();

}  // namespace llarp
