#pragma once

#include "info.hpp"
#include "intro_set.hpp"

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
        Ed25519SecretKey _idkey;
        Ed25519SecretKey _enckey;
        Ed25519Hash derivedSignKey;
        uint64_t version = llarp::constants::proto_version;

        // public service info
        ServiceInfo pub;

        // regenerate secret keys
        void regenerate_keys();

        std::string bt_encode() const;

        void bt_decode(std::string);

        bool KeyExchange(
            path_dh_func dh, SharedSecret& sharedkey, const ServiceInfo& other, const KeyExchangeNonce& N) const;

        std::optional<EncryptedIntroSet> encrypt_and_sign_introset(
            const IntroSetOld& i, std::chrono::milliseconds now) const;

        bool Sign(Signature& sig, uint8_t* buf, size_t size) const;

        /// zero out all secret key members
        void Clear();
    };

    inline bool operator==(const Identity& lhs, const Identity& rhs)
    {
        return std::tie(lhs._enckey, lhs._idkey, lhs.version) == std::tie(rhs._enckey, rhs._idkey, rhs.version);
    }
}  // namespace llarp::service
