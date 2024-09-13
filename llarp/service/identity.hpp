#pragma once

#include "info.hpp"
#include "intro_set.hpp"
#include "vanity.hpp"

#include <llarp/constants/proto.hpp>
#include <llarp/crypto/key_manager.hpp>
#include <llarp/util/buffer.hpp>

#include <memory>
#include <tuple>

namespace llarp::service
{
    // private keys
    struct Identity
    {
        SecretKey _idkey;
        SecretKey _enckey;
        PrivateKey derivedSignKey;
        PQKeyPair pq;
        uint64_t version = llarp::constants::proto_version;
        VanityNonce vanity;

        // public service info
        ServiceInfo pub;

        // regenerate secret keys
        void regenerate_keys();

        std::string bt_encode() const;

        void bt_decode(std::string);

        bool KeyExchange(
            path_dh_func dh, SharedSecret& sharedkey, const ServiceInfo& other, const KeyExchangeNonce& N) const;

        std::optional<EncryptedIntroSet> encrypt_and_sign_introset(
            const IntroSet& i, std::chrono::milliseconds now) const;

        bool Sign(Signature& sig, uint8_t* buf, size_t size) const;

        /// zero out all secret key members
        void Clear();
    };

    inline bool operator==(const Identity& lhs, const Identity& rhs)
    {
        return std::tie(lhs._enckey, lhs._idkey, lhs.pq, lhs.version, lhs.vanity)
            == std::tie(rhs._enckey, rhs._idkey, rhs.pq, rhs.version, rhs.vanity);
    }
}  // namespace llarp::service
