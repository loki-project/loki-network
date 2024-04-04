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
        static auto logcat = llarp::log::Cat("path-build");

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

        /** For each hop:
            - Generate an Ed keypair for the hop (`shared_key`)
            - Generate a symmetric nonce for subsequent DH
            - Derive the shared secret (`hop.shared`) for DH key-exchange using the ED keypair, hop pubkey, and
                symmetric nonce
            - Encrypt the hop info in-place using `hop.shared` and the generated symmetric nonce from DH
            - Generate the XOR nonce by hashing the symmetric key from DH (`hop.shared`) and truncating

            Bt-encoded contents:
            - 'n' : symmetric nonce used for DH ey-exchange
            - 's' : shared pubkey used to derive symmetric key
            - 'x' : encrypted payload
                - 'l' : path lifetime
                - 'r' : rxID (the path ID for messages going *to* the hop)
                - 't' : txID (the path ID for messages coming *from* the client/path origin)
                - 'u' : upstream hop RouterID

            All of these 'frames' are inserted sequentially into the list and padded with any needed dummy frames
        */
        inline static std::string serialize_hop(path::PathHopConfig& hop, const RouterID& nextHop)
        {
            std::string hop_payload;

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("l", path::DEFAULT_LIFETIME.count());
                btdp.append("r", hop.rxID.to_view());
                btdp.append("t", hop.txID.to_view());
                btdp.append("u", hop.upstream.to_view());

                hop_payload = std::move(btdp).str();
            }

            SecretKey shared_key;
            crypto::encryption_keygen(shared_key);

            // SharedSecret shared;
            // SymmNonce nonce;
            // nonce.Randomize();
            hop.nonce = SymmNonce::make_random();

            // derive shared key
            if (!crypto::dh_client(hop.shared, hop.rc.router_id(), shared_key, hop.nonce))
            {
                auto err = "DH client failed during hop info encryption!"s;
                log::warning(messages::logcat, "{}", err);
                throw std::runtime_error{err};
            }

            // encrypt hop_info (mutates in-place)
            if (!crypto::xchacha20(
                    reinterpret_cast<unsigned char*>(hop_payload.data()), hop_payload.size(), hop.shared, hop.nonce))
            {
                auto err = "Hop info encryption failed!"s;
                log::warning(messages::logcat, "{}", err);
                throw std::runtime_error{err};
            }

            // generate nonceXOR value self->hop->pathKey
            ShortHash hash;
            crypto::shorthash(hash, hop.shared.data(), hop.shared.size());

            hop.nonceXOR = hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate
            hop.upstream = nextHop;

            oxenc::bt_dict_producer btdp;

            btdp.append("n", hop.nonce.to_view());
            btdp.append("s", shared_key.to_pubkey().to_view());
            btdp.append("x", hop_payload);

            return std::move(btdp).str();
        }

        inline static std::tuple<ustring, ustring, ustring> deserialize_hop(
            oxenc::bt_dict_consumer& btdc, const RouterID& local_pubkey)
        {
            ustring nonce, other_pubkey, hop_payload;

            try
            {
                nonce = btdc.require<ustring>("n");
                other_pubkey = btdc.require<ustring>("s");
                hop_payload = btdc.require<ustring>("x");
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing hop dict:{}", e.what());
                throw;
            }

            SharedSecret shared;
            // derive shared secret using ephemeral pubkey and our secret key (and nonce)
            if (!crypto::dh_server(shared.data(), other_pubkey.data(), local_pubkey.data(), nonce.data()))
            {
                log::info(logcat, "DH server initialization failed during path build");
                throw std::runtime_error{BAD_CRYPTO};
            }

            // decrypt frame with our hop info
            if (!crypto::xchacha20(hop_payload.data(), hop_payload.size(), shared.data(), nonce.data()))
            {
                log::info(logcat, "Decrypt failed on path build request");
                throw std::runtime_error{BAD_CRYPTO};
            }

            return {std::move(nonce), std::move(other_pubkey), std::move(hop_payload)};
        }
    }  // namespace PathBuildMessage

    namespace Onion
    {
        static auto logcat = llarp::log::Cat("onion");

        /** Bt-encoded contents:
            - 'h' : HopID of the next layer of the onion
            - 'n' : Symmetric nonce used to encrypt the layer
            - 'x' : Encrypted payload transmitted to next recipient
        */
        inline static std::string serialize(
            const SymmNonce& nonce, const HopID& hop_id, const std::string_view& payload)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("h", hop_id.to_view());
            btdp.append("n", nonce.to_view());
            btdp.append("x", payload);

            return std::move(btdp).str();
        }

        inline static std::string serialize(const SymmNonce& nonce, const HopID& hop_id, const ustring_view& payload)
        {
            return serialize(
                nonce, hop_id, std::string_view{reinterpret_cast<const char*>(payload.data()), payload.size()});
        }

        inline static std::tuple<ustring, ustring, ustring> deserialize(oxenc::bt_dict_consumer& btdc)
        {
            ustring hopid, nonce, payload;

            try
            {
                hopid = btdc.require<ustring>("h");
                nonce = btdc.require<ustring>("n");
                payload = btdc.require<ustring>("x");
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing onion data:{}", e.what());
                throw;
            }

            return {std::move(hopid), std::move(nonce), std::move(payload)};
        }

    }  //  namespace Onion

}  // namespace llarp
