#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    using namespace oxenc::literals;

    namespace ONION
    {
        static auto logcat = llarp::log::Cat("onion");

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
        // template <oxenc::string_like K, oxenc::string_like T>
        // inline static std::string serialize_hop(K key, const SymmNonce& nonce, T encrypted)
        inline static std::string serialize_hop(
            std::string_view key, const SymmNonce& nonce, std::string_view encrypted)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("k", key);
            btdp.append("n", nonce.to_view());
            btdp.append("x", encrypted);

            return std::move(btdp).str();
        }

        inline static std::tuple<std::string, shared_kx_data> deserialize_decrypt(
            oxenc::bt_dict_consumer&& btdc, const Ed25519SecretKey& local_sk)
        {
            std::string payload;
            shared_kx_data kx_data{};

            try
            {
                kx_data.pubkey.from_string(btdc.require<std::string_view>("k"));
                kx_data.nonce.from_string(btdc.require<std::string_view>("n"));
                payload = btdc.require<std::string_view>("x");
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing onion data: {}", e.what());
                throw std::runtime_error{messages::ERROR_RESPONSE};
            }

            log::trace(logcat, "payload: {}", buffer_printer{payload});

            try
            {
                kx_data.server_dh(local_sk);
                kx_data.decrypt(to_uspan(payload));

                log::trace(logcat, "xchacha -> payload: {}", buffer_printer{payload});

                kx_data.generate_xor();
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Failed to derive and decrypt outer wrapping!");
                throw std::runtime_error{messages::ERROR_RESPONSE};
            }

            return {std::move(payload), std::move(kx_data)};
        }

        inline static std::tuple<RouterID, SymmNonce, std::string> deserialize(oxenc::bt_dict_consumer&& btdc)
        {
            RouterID rid;
            std::string payload;
            SymmNonce nonce;

            try
            {
                rid.from_string(btdc.require<std::string_view>("k"));
                nonce.from_string(btdc.require<std::string_view>("n"));
                payload = btdc.require<std::string_view>("x");
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error{"Exception caught deserializing onion data: {}"_format(e.what())};
            }

            return {std::move(rid), std::move(nonce), std::move(payload)};
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
                    - 'r' : rxID (the path ID for messages going *to* the hop)
                    - 't' : txID (the path ID for messages coming *from* the client/path origin)
                    - 'u' : upstream hop RouterID

                All of these 'frames' are inserted sequentially into the list and padded with any needed dummy frames
            */
            inline static std::string serialize_hop(path::TransitHop& hop)
            {
                std::string hop_payload = hop.bt_encode();

                // client dh key derivation
                hop.kx.client_dh(hop.router_id());
                // encrypt payload
                hop.kx.encrypt(to_uspan(hop_payload));
                // generate nonceXOR value
                hop.kx.generate_xor();

                log::trace(
                    logcat,
                    "Hop serialized; nonce: {}, remote router_id: {}, shared pk: {}, shared secret: {}, payload: {}",
                    hop.kx.nonce.to_string(),
                    hop.router_id().to_string(),
                    hop.kx.pubkey.to_string(),
                    hop.kx.shared_secret.to_string(),
                    buffer_printer{hop_payload});

                return ONION::serialize_hop(hop.kx.pubkey.to_view(), hop.kx.nonce, hop_payload);
            }

            inline static std::shared_ptr<path::TransitHop> deserialize_hop(
                oxenc::bt_dict_consumer&& btdc, Router& r, const RouterID& src)
            {
                std::string payload;
                auto hop = std::make_shared<path::TransitHop>();

                try
                {
                    hop->kx.pubkey.from_string(btdc.require<std::string_view>("k"));
                    hop->kx.nonce.from_string(btdc.require<std::string_view>("n"));
                    payload = btdc.require<std::string_view>("x");
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Exception caught deserializing hop dict: {}", e.what());
                    throw;
                }

                log::trace(
                    logcat,
                    "Hop deserialized; nonce: {}, remote pk: {}, payload: {}",
                    hop->kx.nonce.to_string(),
                    hop->kx.pubkey.to_string(),
                    buffer_printer{payload});

                try
                {
                    hop->kx.server_dh(r.identity());
                    hop->kx.decrypt(to_uspan(payload));
                    hop->kx.generate_xor();

                    log::trace(
                        logcat,
                        "Hop decrypted; nonce: {}, remote pk: {}, payload: {}",
                        hop->kx.nonce.to_string(),
                        hop->kx.pubkey.to_string(),
                        buffer_printer{payload});

                    hop->deserialize(oxenc::bt_dict_consumer{std::move(payload)}, src, r);
                }
                catch (...)
                {
                    log::info(logcat, "Failed to derive and decrypt outer wrapping!");
                    throw std::runtime_error{BAD_CRYPTO};
                }

                log::trace(logcat, "TransitHop data successfully deserialized: {}", hop->to_string());
                return hop;
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
                - 'p' : messages payload
                NOTE: more fields may be added later as needed, hence the namespacing
            */
            inline static std::string serialize(std::string payload, const RouterID& local)
            {
                oxenc::bt_dict_producer btdp;
                btdp.append("i", local.to_view());
                btdp.append("p", payload);
                return std::move(btdp).str();
            }

            inline static std::string serialize_intermediate(std::string payload, const HopID& pivot_txid)
            {
                oxenc::bt_dict_producer btdp;
                btdp.append("i", pivot_txid.to_view());
                btdp.append("p", payload);
                return std::move(btdp).str();
            }

            inline static std::tuple<NetworkAddress, bstring> deserialize(oxenc::bt_dict_consumer& btdc)
            {
                RouterID remote;
                bstring payload;

                try
                {
                    remote.from_string(btdc.require<std::string_view>("i"));
                    payload = btdc.require<bstring>("p");
                    auto sender = NetworkAddress::from_pubkey(remote, true);

                    return {std::move(sender), std::move(payload)};
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error{"Exception caught deserializing path data:{}"_format(e.what())};
                }
            }

            inline static std::tuple<HopID, std::string> deserialize_intermediate(oxenc::bt_dict_consumer&& btdc)
            {
                HopID hop_id;
                std::string payload;

                try
                {
                    hop_id.from_string(btdc.require<std::string_view>("i"));
                    payload = btdc.require<std::string>("p");

                    return {std::move(hop_id), std::move(payload)};
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error{"Exception caught deserializing path data:{}"_format(e.what())};
                }
            }
        }  // namespace DATA
    }      // namespace PATH
}  // namespace llarp
