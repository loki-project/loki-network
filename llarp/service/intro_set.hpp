#pragma once

#include "info.hpp"
#include "intro.hpp"
#include "types.hpp"

#include <llarp/address/ip_range.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/dns/srv_data.hpp>
#include <llarp/net/traffic_policy.hpp>
#include <llarp/util/time.hpp>

#include <algorithm>
#include <functional>
#include <iostream>
#include <optional>
#include <vector>

namespace llarp::service
{
    constexpr std::size_t MAX_INTROSET_SIZE = 4096;
    // 10 seconds clock skew permitted for introset expiration
    constexpr std::chrono::milliseconds MAX_INTROSET_TIME_DELTA = 10s;

    struct IntroSetOld
    {
        ServiceInfo address_keys;
        IntroductionSet_old intros;
        std::vector<dns::SRVData> SRVs;
        std::chrono::milliseconds time_signed = 0s;

        IntroSetOld() = default;

        explicit IntroSetOld(std::string bt_payload);

        /// ethertypes we advertise that we speak
        std::vector<ProtocolType> supported_protocols;
        /// aonnuce that these ranges are reachable via our endpoint
        /// only set when we support exit traffic ethertype is supported
        std::set<IPRange> _routed_ranges;  // TESTNET: TOFIX: Move into exit policy!

        /// policies about traffic that we are willing to carry
        /// a protocol/range whitelist or blacklist
        /// only set when we support exit traffic ethertype
        std::optional<net::ExitPolicy> exit_policy = std::nullopt;

        Signature signature;
        uint64_t version = llarp::constants::proto_version;

        bool OtherIsNewer(const IntroSetOld& other) const { return time_signed < other.time_signed; }

        std::string to_string() const;

        std::chrono::milliseconds GetNewestIntroExpiration() const;

        bool HasExpiredIntros(std::chrono::milliseconds now) const;

        /// return true if any of our intros expires soon given a delta
        bool HasStaleIntros(std::chrono::milliseconds now, std::chrono::milliseconds delta) const;

        bool IsExpired(std::chrono::milliseconds now) const;

        std::vector<llarp::dns::SRVData> GetMatchingSRVRecords(std::string_view service_proto) const;

        std::string bt_encode() const;

        bool bt_decode(std::string_view buf);

        void bt_decode(oxenc::bt_dict_consumer& btdc);

        bool verify(std::chrono::milliseconds now) const;

        nlohmann::json ExtractStatus() const;

        static constexpr bool to_string_formattable = true;
    };

    inline bool operator<(const IntroSetOld& lhs, const IntroSetOld& rhs)
    {
        return lhs.address_keys < rhs.address_keys;
    }

    inline bool operator==(const IntroSetOld& lhs, const IntroSetOld& rhs)
    {
        return std::tie(lhs.address_keys, lhs.intros, lhs.time_signed, lhs.version, lhs.signature)
            == std::tie(rhs.address_keys, rhs.intros, rhs.time_signed, rhs.version, rhs.signature);
    }

    inline bool operator!=(const IntroSetOld& lhs, const IntroSetOld& rhs)
    {
        return !(lhs == rhs);
    }

    /// public version of the introset that is encrypted
    struct EncryptedIntroSet
    {
      private:
        explicit EncryptedIntroSet(std::string bt_payload);
        bool bt_decode(oxenc::bt_dict_consumer& btdc);

      public:
        PubKey derived_signing_key;
        std::chrono::milliseconds signed_at = 0s;
        ustring introset_payload;
        SymmNonce nonce;
        Signature sig;

        EncryptedIntroSet() = default;

        explicit EncryptedIntroSet(
            std::string signing_key,
            std::chrono::milliseconds signed_at,
            std::string enc_payload,
            std::string nonce,
            std::string sig);

        bool sign(const Ed25519Hash& k);

        bool is_expired(std::chrono::milliseconds now = time_now_ms()) const;

        std::string bt_encode() const;

        bool bt_decode(std::string_view buf);

        bool other_is_newer(const EncryptedIntroSet& other) const;

        /// verify signature and timestamp
        bool verify() const;

        static bool verify(uint8_t* introset, size_t introset_size, uint8_t* key, uint8_t* sig);

        static bool verify(std::string introset, std::string key, std::string sig);

        // this constructor will throw if ::bt_decode fails
        static std::optional<EncryptedIntroSet> construct(std::string bt);

        std::string to_string() const;

        nlohmann::json ExtractStatus() const;

        std::optional<IntroSetOld> decrypt(const PubKey& root) const;
        static constexpr bool to_string_formattable = true;
    };

    inline bool operator<(const EncryptedIntroSet& lhs, const EncryptedIntroSet& rhs)
    {
        return lhs.derived_signing_key < rhs.derived_signing_key;
    }

    inline bool operator==(const EncryptedIntroSet& lhs, const EncryptedIntroSet& rhs)
    {
        return std::tie(lhs.signed_at, lhs.derived_signing_key, lhs.nonce, lhs.sig)
            == std::tie(rhs.signed_at, rhs.derived_signing_key, rhs.nonce, rhs.sig);
    }

    inline bool operator!=(const EncryptedIntroSet& lhs, const EncryptedIntroSet& rhs)
    {
        return !(lhs == rhs);
    }

    using EncryptedIntroSetLookupHandler = std::function<void(const std::vector<EncryptedIntroSet>&)>;
    using IntroSetLookupHandler = std::function<void(const std::vector<IntroSetOld>&)>;

}  // namespace llarp::service
