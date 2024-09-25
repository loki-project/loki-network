#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    using namespace oxenc::literals;

    namespace Frames
    {
        static auto logcat = llarp::log::Cat("path-build-frames");

        inline static std::string serialize(std::vector<std::string>&& frames)
        {
            return oxenc::bt_serialize(std::move(frames));
        }

        inline static std::vector<std::string> deserialize(std::string_view&& buf)
        {
            return oxenc::bt_deserialize<std::vector<std::string>>(buf);
        }
    }  // namespace Frames

    namespace PathData
    {
        static auto logcat = llarp::log::Cat("path-data");

        /** Fields for transmitting Path Data:
            - 'b' : request/command body
            - 's' : RouterID of sender
            NOTE: more fields may be added later as needed, hence the namespacing
        */
        inline static std::string serialize(std::string body, const RouterID& local)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("b", body);
            btdp.append("s", local.to_view());
            return std::move(btdp).str();
        }

        inline static std::tuple<NetworkAddress, bstring> deserialize(oxenc::bt_dict_consumer& btdc)
        {
            RouterID remote;
            bstring body;

            try
            {
                body = btdc.require<bstring>("b");
                remote.from_string(btdc.require<std::string_view>("s"));
                auto sender = NetworkAddress::from_pubkey(remote, true);

                return {std::move(sender), std::move(body)};
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing path data:{}", e.what());
                throw;
            }
        }
    }  // namespace PathData

    namespace PathControl
    {
        static auto logcat = llarp::log::Cat("path-control");

        /** Fields for transmitting Path Control:
            - 'e' : request endpoint being invoked
            - 'r' : request body
        */
        inline static std::string serialize(std::string endpoint, std::string body)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("e", endpoint);
            btdp.append("r", body);
            return std::move(btdp).str();
        }

        inline static std::tuple<std::string, std::string> deserialize(oxenc::bt_dict_consumer& btdc)
        {
            std::string endpoint, body;

            try
            {
                endpoint = btdc.require<std::string>("e");
                body = btdc.require<std::string>("r");
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing path control:{}", e.what());
                throw;
            }

            return {std::move(endpoint), std::move(body)};
        }
    }  // namespace PathControl

    namespace PathBuildMessage
    {
        static auto logcat = llarp::log::Cat("path-build");

        inline constexpr auto bad_frames = "BAD_FRAMES"sv;
        inline constexpr auto bad_crypto = "BAD_CRYPTO"sv;
        inline constexpr auto no_transit = "NOT ALLOWING TRANSIT"sv;
        inline constexpr auto bad_pathid = "BAD PATH ID"sv;
        inline constexpr auto bad_lifetime = "BAD PATH LIFETIME (TOO LONG)"sv;

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
            - 'n' : symmetric nonce used for DH key-exchange
            - 's' : shared pubkey used to derive symmetric key
            - 'x' : encrypted payload
                - 'l' : path lifetime
                - 'r' : rxID (the path ID for messages going *to* the hop)
                - 't' : txID (the path ID for messages coming *from* the client/path origin)
                - 'u' : upstream hop RouterID

            All of these 'frames' are inserted sequentially into the list and padded with any needed dummy frames
        */
        inline static std::string serialize_hop(path::PathHopConfig& hop)
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

            Ed25519SecretKey ephemeral_key;
            crypto::identity_keygen(ephemeral_key);

            hop.nonce = SymmNonce::make_random();

            crypto::derive_encrypt_outer_wrapping(
                ephemeral_key, hop.shared, hop.nonce, hop.rc.router_id(), to_uspan(hop_payload));

            // generate nonceXOR value self->hop->pathKey
            ShortHash xor_hash;
            crypto::shorthash(xor_hash, hop.shared.data(), hop.shared.size());

            hop.nonceXOR = xor_hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate

            log::trace(
                logcat,
                "Hop serialized; nonce: {}, remote router_id: {}, shared pk: {}, shared secret: {}, payload: {}",
                hop.nonce.to_string(),
                hop.rc.router_id().to_string(),
                ephemeral_key.to_pubkey().to_string(),
                hop.shared.to_string(),
                buffer_printer{hop_payload});

            oxenc::bt_dict_producer btdp;

            btdp.append("n", hop.nonce.to_view());
            btdp.append("s", ephemeral_key.to_pubkey().to_view());
            btdp.append("x", hop_payload);

            return std::move(btdp).str();
        }

        inline static std::tuple<SymmNonce, PubKey, ustring> deserialize_hop(
            oxenc::bt_dict_consumer&& btdc, const Ed25519SecretKey& local_sk)
        {
            SymmNonce nonce;
            PubKey remote_pk;
            ustring hop_payload;

            try
            {
                nonce.from_string(btdc.require<std::string_view>("n"));
                remote_pk.from_string(btdc.require<std::string_view>("s"));
                hop_payload = btdc.require<ustring>("x");
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing hop dict:{}", e.what());
                throw;
            }

            log::trace(
                logcat,
                "Hop deserialized; nonce: {}, remote pk: {}, payload: {}",
                nonce.to_string(),
                remote_pk.to_string(),
                buffer_printer{hop_payload});

            try
            {
                crypto::derive_decrypt_outer_wrapping(local_sk, remote_pk, nonce, to_uspan(hop_payload));
            }
            catch (...)
            {
                log::info(logcat, "Failed to derive and decrypt outer wrapping!");
                throw std::runtime_error{BAD_CRYPTO};
            }

            log::trace(
                logcat,
                "Hop decrypted; nonce: {}, remote pk: {}, payload: {}",
                nonce.to_string(),
                remote_pk.to_string(),
                buffer_printer{hop_payload});

            return {std::move(nonce), std::move(remote_pk), std::move(hop_payload)};
        }
    }  // namespace PathBuildMessage
}  // namespace llarp
