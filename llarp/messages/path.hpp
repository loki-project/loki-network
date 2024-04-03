#pragma once

#include "common.hpp"

namespace llarp
{

    namespace PathData
    {
        // this might be totally superfluous, but if we want to add more to the data messages,
        // there is a bespoke place to do exactly that
        inline static std::string serialize(std::string body)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("BODY", body);
            return std::move(btdp).str();
        }
    }  // namespace PathData

    namespace PathControl
    {
        inline static std::string serialize(std::string method, std::string body)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("BODY", body);
            btdp.append("METHOD", method);
            return std::move(btdp).str();
        }
    }  // namespace PathControl

    namespace PathBuildMessage
    {
        inline auto bad_frames = "BAD_FRAMES"sv;
        inline auto bad_crypto = "BAD_CRYPTO"sv;
        inline auto no_transit = "NOT ALLOWING TRANSIT"sv;
        inline auto bad_pathid = "BAD PATH ID"sv;
        inline auto bad_lifetime = "BAD PATH LIFETIME (TOO LONG)"sv;

        inline const auto NO_TRANSIT = messages::serialize_response({{messages::STATUS_KEY, no_transit}});
        inline const auto BAD_LIFETIME = messages::serialize_response({{messages::STATUS_KEY, bad_lifetime}});
        inline const auto BAD_FRAMES = messages::serialize_response({{messages::STATUS_KEY, bad_frames}});
        inline const auto BAD_PATHID = messages::serialize_response({{messages::STATUS_KEY, bad_pathid}});
        inline const auto BAD_CRYPTO = messages::serialize_response({{messages::STATUS_KEY, bad_crypto}});

        /* - For each hop:
         * setup_hop_keys:
         *   - Generate Ed keypair for the hop. ("commkey")
         *   - Use that key and the hop's pubkey for DH key exchange (makes "hop.shared")
         *     - Note: this *was* using hop's "enckey" but we're getting rid of that
         *   - hop's "upstream" RouterID is next hop, or that hop's ID if it is terminal hop
         *   - hop's chacha nonce is hash of symmetric key (hop.shared) from DH
         *   - hop's "txID" and "rxID" are chosen before this step
         *     - txID is the path ID for messages coming *from* the client/path origin
         *     - rxID is the path ID for messages going *to* it.
         *
         * serialize:
         *   - bt-encode "hop info":
         *     - path lifetime
         *     - protocol version
         *     - txID
         *     - rxID
         *     - nonce
         *     - upstream hop RouterID
         *     - ephemeral public key (for DH)
         *   - generate *second* ephemeral Ed keypair... ("framekey") TODO: why?
         *   - generate DH symmetric key using "framekey" and hop's pubkey
         *   - generate nonce for second encryption
         *   - encrypt "hop info" using this symmetric key
         *   - bt-encode nonce, "framekey" pubkey, encrypted "hop info"
         *
         *  all of these "frames" go in a list, along with any needed dummy frames
         */
        inline static void setup_hop_keys(path::PathHopConfig& hop, const RouterID& nextHop)
        {
            // generate key
            crypto::encryption_keygen(hop.commkey);

            hop.nonce.Randomize();
            // do key exchange
            if (!crypto::dh_client(hop.shared, hop.rc.router_id(), hop.commkey, hop.nonce))
            {
                auto err = fmt::format("Failed to generate shared key for path build!");
                log::warning(messages::logcat, "{}", err);
                throw std::runtime_error{std::move(err)};
            }
            // generate nonceXOR value self->hop->pathKey
            ShortHash hash;
            crypto::shorthash(hash, hop.shared.data(), hop.shared.size());
            hop.nonceXOR = hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate

            hop.upstream = nextHop;
        }

        inline static std::string serialize(const path::PathHopConfig& hop)
        {
            std::string hop_info;

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("COMMKEY", hop.commkey.to_pubkey().to_view());
                btdp.append("LIFETIME", path::DEFAULT_LIFETIME.count());
                btdp.append("NONCE", hop.nonce.to_view());
                btdp.append("RX", hop.rxID.to_view());
                btdp.append("TX", hop.txID.to_view());
                btdp.append("UPSTREAM", hop.upstream.to_view());

                hop_info = std::move(btdp).str();
            }

            SecretKey framekey;
            crypto::encryption_keygen(framekey);

            SharedSecret shared;
            SymmNonce outer_nonce;
            outer_nonce.Randomize();

            // derive (outer) shared key
            if (!crypto::dh_client(shared, hop.rc.router_id(), framekey, outer_nonce))
            {
                auto err = "DH client failed during hop info encryption!"s;
                log::warning(messages::logcat, "{}", err);
                throw std::runtime_error{err};
            }

            // encrypt hop_info (mutates in-place)
            if (!crypto::xchacha20(
                    reinterpret_cast<unsigned char*>(hop_info.data()), hop_info.size(), shared, outer_nonce))
            {
                auto err = "Hop info encryption failed!"s;
                log::warning(messages::logcat, "{}", err);
                throw std::runtime_error{err};
            }

            oxenc::bt_dict_producer btdp;

            btdp.append("ENCRYPTED", hop_info);
            btdp.append("NONCE", outer_nonce.to_view());
            btdp.append("PUBKEY", framekey.to_pubkey().to_view());

            return std::move(btdp).str();
        }
    }  // namespace PathBuildMessage

    namespace RelayCommitMessage
    {}

    namespace RelayStatusMessage
    {}

    namespace PathConfirmMessage
    {}

    namespace PathLatencyMessage
    {}

    namespace PathTransferMessage
    {}

}  // namespace llarp
