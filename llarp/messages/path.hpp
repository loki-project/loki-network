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

        inline static void setup_hop_keys(path::PathHopConfig& hop, const RouterID& nextHop)
        {
            // generate key
            crypto::encryption_keygen(hop.commkey);

            hop.nonce.Randomize();
            // do key exchange
            if (!crypto::dh_client(hop.shared, hop.rc.router_id(), hop.commkey, hop.nonce))
            {
                auto err = fmt::format("Failed to generate shared key for path build!");
                log::warning(path_cat, err);
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

                btdp.append("COMMKEY", hop.commkey.to_pubkey().ToView());
                btdp.append("LIFETIME", path::DEFAULT_LIFETIME.count());
                btdp.append("NONCE", hop.nonce.ToView());
                btdp.append("RX", hop.rxID.ToView());
                btdp.append("TX", hop.txID.ToView());
                btdp.append("UPSTREAM", hop.upstream.ToView());

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
                log::warning(path_cat, "DH client failed during hop info encryption!");
                throw std::runtime_error{"DH failed during hop info encryption"};
            }

            // encrypt hop_info (mutates in-place)
            if (!crypto::xchacha20(
                    reinterpret_cast<unsigned char*>(hop_info.data()), hop_info.size(), shared, outer_nonce))
            {
                log::warning(path_cat, "Hop info encryption failed!");
                throw std::runtime_error{"Hop info encryption failed"};
            }

            std::string hashed_data;

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("ENCRYPTED", hop_info);
                btdp.append("NONCE", outer_nonce.ToView());
                btdp.append("PUBKEY", framekey.to_pubkey().ToView());

                hashed_data = std::move(btdp).str();
            }

            std::string hash;
            hash.reserve(SHORTHASHSIZE);

            if (!crypto::hmac(
                    reinterpret_cast<uint8_t*>(hash.data()),
                    reinterpret_cast<uint8_t*>(hashed_data.data()),
                    hashed_data.size(),
                    shared))
            {
                log::warning(path_cat, "Failed to generate HMAC for hop info");
                throw std::runtime_error{"Failed to generate HMAC for hop info"};
            }

            oxenc::bt_dict_producer btdp;

            btdp.append("FRAME", hashed_data);
            btdp.append("HASH", hash);

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
