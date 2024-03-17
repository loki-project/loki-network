#pragma once

#include "info.hpp"
#include "intro_set.hpp"
#include "vanity.hpp"

#include <llarp/constants/proto.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/util/buffer.hpp>

#include <memory>
#include <tuple>

namespace llarp::service
{
    // private keys
    struct Identity
    {
        SecretKey enckey;
        SecretKey signkey;
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

        /// @param needBackup determines whether existing keys will be cycled
        void ensure_keys(fs::path fpath, bool needBackup);

        bool KeyExchange(
            path_dh_func dh, SharedSecret& sharedkey, const ServiceInfo& other, const KeyExchangeNonce& N) const;

        std::optional<EncryptedIntroSet> encrypt_and_sign_introset(const IntroSet& i, llarp_time_t now) const;

        bool Sign(Signature& sig, uint8_t* buf, size_t size) const;

        /// zero out all secret key members
        void Clear();
    };

    inline bool operator==(const Identity& lhs, const Identity& rhs)
    {
        return std::tie(lhs.enckey, lhs.signkey, lhs.pq, lhs.version, lhs.vanity)
            == std::tie(rhs.enckey, rhs.signkey, rhs.pq, rhs.version, rhs.vanity);
    }
}  // namespace llarp::service
