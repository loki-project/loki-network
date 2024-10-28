#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    using namespace oxenc::literals;

    namespace ONION
    {
        inline static std::string serialize_frames(std::vector<std::string>&& frames)
        {
            return oxenc::bt_serialize(std::move(frames));
        }

        inline static std::vector<std::string> deserialize_frames(std::string_view&& buf)
        {
            return oxenc::bt_deserialize<std::vector<std::string>>(buf);
        }

        /** Bt-encoded contents:
            - 'k' : Next upstream HopID (path messages) OR shared pubkey (path builds)
            - 'n' : Symmetric nonce used to encrypt the layer
            - 'x' : Encrypted payload transmitted to next recipient
        */
        template <oxenc::string_like K, oxenc::string_like T>
        inline static std::string serialize_hop(K key, const SymmNonce& nonce, T encrypted)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("k", key);
            btdp.append("n", nonce.to_view());
            btdp.append("x", encrypted);

            return std::move(btdp).str();
        }

        inline static std::tuple<HopID, SymmNonce, std::string> deserialize_hop(oxenc::bt_dict_consumer&& btdc)
        {
            HopID hop_id;
            std::string payload;
            SymmNonce nonce;

            try
            {
                hop_id.from_string(btdc.require<std::string_view>("k"));
                nonce.from_string(btdc.require<std::string_view>("n"));
                payload = btdc.require<std::string_view>("x");
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error{"Exception caught deserializing onion data: {}"_format(e.what())};
            }

            return {std::move(hop_id), std::move(nonce), std::move(payload)};
        }

    }  // namespace ONION

    namespace PATH
    {
        namespace BUILD
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
                - Derive the shared secret (`hop.shared`) for DH key-exchange using the Ed keypair, hop pubkey, and
                    symmetric nonce
                - Encrypt the hop info in-place using `hop.shared` and the generated symmetric nonce from DH
                - Generate the XOR nonce by hashing the symmetric key from DH (`hop.shared`) and truncating

                Bt-encoded contents:
                - 'k' : shared pubkey used to derive symmetric key
                - 'n' : symmetric nonce used for DH key-exchange
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

                return ONION::serialize_hop(ephemeral_key.to_pubkey().to_view(), hop.nonce, hop_payload);
            }

            inline static std::tuple<SymmNonce, SharedSecret, ustring> deserialize_hop(
                oxenc::bt_dict_consumer&& btdc, const Ed25519SecretKey& local_sk)
            {
                SymmNonce nonce;
                PubKey remote_pk;
                ustring hop_payload;
                SharedSecret shared;

                try
                {
                    remote_pk.from_string(btdc.require<std::string_view>("k"));
                    nonce.from_string(btdc.require<std::string_view>("n"));
                    hop_payload = btdc.require<ustring_view>("x");
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Exception caught deserializing hop dict: {}", e.what());
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
                    crypto::derive_decrypt_outer_wrapping(local_sk, shared, remote_pk, nonce, to_uspan(hop_payload));
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

                return {std::move(nonce), std::move(shared), std::move(hop_payload)};
            }
        }  // namespace BUILD

        namespace CONTROL
        {
            /** Fields for transmitting Path Control:
                - 'e' : request endpoint being invoked
                - 'p' : request payload
            */
            inline static std::string serialize(std::string endpoint, std::string payload)
            {
                oxenc::bt_dict_producer btdp;
                btdp.append("e", endpoint);
                btdp.append("p", payload);
                return std::move(btdp).str();
            }

            inline static std::tuple<std::string, std::string> deserialize(oxenc::bt_dict_consumer&& btdc)
            {
                std::string endpoint, payload;

                try
                {
                    endpoint = btdc.require<std::string>("e");
                    payload = btdc.require<std::string>("p");
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error{"Exception caught deserializing path control: {}"_format(e.what())};
                }

                return {std::move(endpoint), std::move(payload)};
            }
        }  // namespace CONTROL

        namespace DATA
        {
            /** Fields for transmitting Path Data:
                - 'i' : RouterID of sender
                - 'p' : request/command payload
                NOTE: more fields may be added later as needed, hence the namespacing
            */
            inline static std::string serialize(std::string payload, const RouterID& local)
            {
                oxenc::bt_dict_producer btdp;
                btdp.append("i", local.to_view());
                btdp.append("p", payload);
                return std::move(btdp).str();
            }

            inline static std::tuple<NetworkAddress, bstring> deserialize(oxenc::bt_dict_consumer& btdc)
            {
                RouterID remote;
                bstring body;

                try
                {
                    remote.from_string(btdc.require<std::string_view>("i"));
                    body = btdc.require<bstring>("p");
                    auto sender = NetworkAddress::from_pubkey(remote, true);

                    return {std::move(sender), std::move(body)};
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error{"Exception caught deserializing path data:{}"_format(e.what())};
                }
            }
        }  // namespace DATA
    }      // namespace PATH
}  // namespace llarp
