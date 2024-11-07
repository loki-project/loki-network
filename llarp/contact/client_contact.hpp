#pragma once

#include "client_intro.hpp"
#include "router_id.hpp"

#include <llarp/constants/version.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dht/key.hpp>
#include <llarp/dns/srv_data.hpp>
#include <llarp/net/net.hpp>
#include <llarp/net/traffic_policy.hpp>
#include <llarp/router_version.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/file.hpp>
#include <llarp/util/time.hpp>

#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>
#include <oxenc/bt_producer.h>

#include <functional>
#include <vector>

namespace llarp
{
    struct EncryptedClientContact;

    namespace dht
    {
        struct CCNode;
    }

    namespace handlers
    {
        class SessionEndpoint;
    }

    enum protocol_flag : uint16_t
    {
        CONTROL = 1 << 0,
        IPV4 = 1 << 1,
        IPV6 = 1 << 2,
        EXIT = 1 << 3,
        AUTH = 1 << 4,
        TCP2QUIC = 1 << 5,
    };

    // TESTNET:
    inline static constexpr auto CC_PUBLISH_INTERVAL{30s};

    /** ClientContact
        On the wire we encode the data as a dict containing:
            - "" : the CC format version, which must be == ClientContact::VERSION to be parsed successfully
            - "a" : public key of the remote client instance
            - "e" : (optional) exit policy containing sublists of accepted protocols and routed IP ranges
            - "i" : list of client introductions corresponding to the different pivots through which paths can be built
                    to the client instance
            - "p" : supported protocols indicating the traffic accepted by the client instance; this indicates if the
                    client is embedded and therefore requires a tunneled connection. Serialized as a bitwise flag of
                    above protocol_flag enums
            - "s" : (optional) SRV records for lokinet DNS lookup
    */
    struct ClientContact
    {
        friend struct EncryptedClientContact;
        friend class handlers::SessionEndpoint;

        inline static constexpr uint8_t CC_VERSION{0};
        inline static constexpr size_t MAX_CC_SIZE{4096};

        ~ClientContact() = default;

      protected:
        ClientContact() = default;
        ClientContact(std::string&& buf);

        ClientContact(
            Ed25519PrivateData private_data,
            PubKey pk,
            const std::unordered_set<dns::SRVData>& srvs,
            uint16_t proto_flags,
            std::optional<net::ExitPolicy> policy = std::nullopt);

        /** Parameters:
            - `private_data` : derived private subkey data
            - `pubkey` : master identity key pubkey
            - `srvs` : SRV records (optional, can be empty)
            - `proto_flags` : client-supported protocols
            - `policy` : exit-related traffic policy (optional)
         */
        static ClientContact generate(
            Ed25519PrivateData&& private_data,
            PubKey&& pubkey,
            const std::unordered_set<dns::SRVData>& srvs,
            uint16_t proto_flags,
            std::optional<net::ExitPolicy> policy = std::nullopt);

        EncryptedClientContact encrypt_and_sign() const;

        template <typename... Opt>
        void regenerate(intro_set iset, Opt&&... args)
        {
            handle_updated_field(std::forward<Opt>(args)...);
            regenerate(std::move(iset));
        }

        void regenerate(intro_set iset)
        {
            handle_updated_field(std::move(iset));
            _regenerate();
        }

        Ed25519PrivateData derived_privatekey;

        PubKey pubkey;

        intro_set intros;
        std::unordered_set<dns::SRVData> SRVs;

        uint16_t protos;

        // In exit mode, we advertise our policy for accepted traffic and the corresponding ranges
        std::optional<net::ExitPolicy> exit_policy;

        bool is_expired(std::chrono::milliseconds now = llarp::time_now_ms()) const;

        void bt_encode(std::vector<unsigned char>& buf) const;

        size_t bt_encode(oxenc::bt_dict_producer&& btdp) const;

        // Throws like a MF (for now)
        void bt_decode(std::string_view buf);

        // Throws if unsuccessful, must take BTDC in invocation
        void bt_decode(oxenc::bt_dict_consumer&& btdc);

      private:
        void _regenerate();

        void handle_updated_field(uint16_t p);
        void handle_updated_field(intro_set iset);
        void handle_updated_field(std::unordered_set<dns::SRVData> srvs);

      public:
        bool operator==(const ClientContact& other) const
        {
            return std::tie(derived_privatekey, pubkey, intros, SRVs, protos, exit_policy)
                == std::tie(
                       other.derived_privatekey,
                       other.pubkey,
                       other.intros,
                       other.SRVs,
                       other.protos,
                       other.exit_policy);
        }

        bool operator!=(const ClientContact& other) const { return !(*this == other); }

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

    /** EncryptedClientContact
            "i" blinded local PubKey (routerID)
            "n" nounce
            "t" signing time
            "x" encrypted payload
            "~" signature   (signed with blinded derived scalar `b`)
    */
    struct EncryptedClientContact
    {
        friend struct dht::CCNode;
        friend struct ClientContact;

        EncryptedClientContact() : nonce{SymmNonce::make_random()}, encrypted(ClientContact::MAX_CC_SIZE) {}

        static EncryptedClientContact deserialize(std::string_view buf);

      protected:
        explicit EncryptedClientContact(std::string_view buf);

        PubKey blinded_pubkey;
        SymmNonce nonce;
        std::chrono::milliseconds signed_at{0s};
        std::vector<unsigned char> encrypted;
        Signature sig{};

        std::string _bt_payload;

        // Does not encode signature, meant to be called prior to signing
        void bt_encode(oxenc::bt_dict_producer& btdp) const;

        void bt_decode(oxenc::bt_dict_consumer&& btdc);

      public:
        dht::Key_t key() const { return dht::Key_t{blinded_pubkey.data()}; }

        std::optional<ClientContact> decrypt(const PubKey& root);

        std::string_view bt_payload() const { return _bt_payload; }

        bool verify() const;

        bool is_expired(std::chrono::milliseconds now = time_now_ms()) const;
    };
}  //  namespace llarp
