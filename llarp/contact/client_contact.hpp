#pragma once

#include "client_intro.hpp"
#include "router_id.hpp"

#include <llarp/constants/version.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dns/srv_data.hpp>
#include <llarp/net/net.hpp>
#include <llarp/net/traffic_policy.hpp>
#include <llarp/router_version.hpp>
#include <llarp/service/types.hpp>
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

    // TODO: add version to `` field to match RelayContact

    /** ClientContact

        On the wire we encode the data as a dict containing:
            - "" : the CC format version, which must be == ClientContact::VERSION to be parsed successfully
            - "a" : public key of the remote client instance
            - "i" : list of client introductions corresponding to the different pivots through which paths can be built
                    to the client instance
            - "p" : supported protocols indicating the traffic accepted by the client instance; this indicates if the
                    client is embedded and therefore requires a tunneled connection
            - "s" : SRV records for lokinet DNS lookup
    */
    struct ClientContact
    {
        static constexpr uint8_t CC_VERSION{0};

        ClientContact() = default;
        ClientContact(std::string_view buf);

        PubKey pubkey;

        intro_set intros;
        std::vector<dns::SRVData> SRVs;
        std::chrono::milliseconds signed_at{0s};

        std::vector<service::ProtocolType> supported_protos;

        // In exit mode, we advertise our policy for accepted traffic and the corresponding ranges
        std::optional<net::ExitPolicy> exit_policy;

        Signature signature;

        bool is_expired(std::chrono::milliseconds now = llarp::time_now_ms()) const;

        std::string bt_encode() const;

        // Does not throw, returns true/false
        bool bt_decode(std::string_view buf);

      protected:
        // Throws if unsuccessful, must take BTDC in invocation
        void bt_decode(oxenc::bt_dict_consumer&& btdc);

      public:
        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

    /**
        EncryptedClientContact
            "i" blinded local routerID
            "n" nounce
            "t" signing time
            "x" same
            "~" signature
     */
    struct EncryptedClientContact
    {
        PubKey blinded_pubkey;
        SymmNonce nonce;
        std::chrono::milliseconds signed_at{0s};
        std::vector<unsigned char> payload;
        Signature sig;
    };
}  //  namespace llarp
