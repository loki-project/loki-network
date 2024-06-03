#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>

namespace llarp
{
    namespace Frames
    {
        static auto logcat = llarp::log::Cat("path-build-frames");

        inline static std::string serialize(std::vector<std::string>& frames)
        {
            oxenc::bt_list_producer btlp;

            for (auto& f : frames)
                btlp.append(std::move(f));

            return std::move(btlp).str();
        }

        inline static std::string serialize(std::deque<ustring>& frames)
        {
            oxenc::bt_list_producer btlp;

            for (auto& f : frames)
                btlp.append(std::move(f));

            return std::move(btlp).str();
        }

        inline static std::deque<ustring> deserialize(oxenc::bt_list_consumer& btlc)
        {
            try
            {
                std::deque<ustring> ret{};

                while (not btlc.is_finished())
                    ret.push_back(btlc.consume<ustring>());

                return ret;
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing path frames:{}", e.what());
                throw;
            }
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

            hop.nonce = SymmNonce::make_random();

            crypto::derive_encrypt_outer_wrapping(
                shared_key, hop.shared, hop.nonce, hop.rc.router_id(), to_usv(hop_payload));

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
}  // namespace llarp
