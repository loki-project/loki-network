#pragma once

#include "path.hpp"

#include <llarp/address/address.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    /** Fields for initiating sessions:
        - 'k' : shared pubkey used to derive symmetric key
        - 'n' : symmetric nonce
        - 'x' : encrypted payload
            - 'i' : RouterID of initiator
            - 'p' : HopID at the pivot taken from local ClientIntro
            - 'r' : HopID at the pivot taken from remote's ClientIntro
            - 's' : session_tag for current session
            - 't' : Use Tun interface (bool)
            - 'u' : Authentication field
                - bt-encoded dict, values TBD
    */
    namespace InitiateSession
    {
        static auto logcat = llarp::log::Cat("session-init");

        inline const auto AUTH_ERROR = messages::serialize_response({{messages::STATUS_KEY, "AUTH ERROR"}});
        inline const auto BAD_PATH = messages::serialize_response({{messages::STATUS_KEY, "BAD PATH"}});

        inline static std::tuple<std::string, shared_kx_data> serialize_encrypt(
            const RouterID& local,
            const RouterID& remote,
            HopID local_pivot_txid,
            HopID remote_pivot_txid,
            std::optional<std::string_view> auth_token,
            bool use_tun)
        {
            try
            {
                std::string payload;

                {
                    oxenc::bt_dict_producer btdp;

                    btdp.append("i", local.to_view());
                    btdp.append("p", local_pivot_txid.to_view());
                    btdp.append("r", remote_pivot_txid.to_view());
                    // btdp.append("s", tag.view());
                    btdp.append("t", use_tun);
                    // TOTHINK: this auth field
                    if (auth_token)
                        btdp.append("u", *auth_token);

                    payload = std::move(btdp).str();
                }

                auto kx_data = shared_kx_data::generate();

                kx_data.client_dh(remote);
                kx_data.encrypt(payload);
                kx_data.generate_xor();

                auto new_payload = ONION::serialize_hop(kx_data.pubkey.to_view(), kx_data.nonce, std::move(payload));

                return {PATH::CONTROL::serialize("session_init", std::move(new_payload)), std::move(kx_data)};
            }
            catch (const std::exception& e)
            {
                log::error(messages::logcat, "Exception caught encrypting session initiation message: {}", e.what());
                throw;
            }
        };

        inline static std::tuple<shared_kx_data, NetworkAddress, HopID, HopID, bool, std::optional<std::string>>
        decrypt_deserialize(oxenc::bt_dict_consumer&& outer_btdc, const Ed25519SecretKey& local)
        {
            SymmNonce nonce;
            PubKey shared_pubkey;
            std::string payload;
            SharedSecret shared;
            shared_kx_data kx_data{};

            try
            {
                std::tie(payload, kx_data) = ONION::deserialize_decrypt(std::move(outer_btdc), local);
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing/decrypting hop dict: {}", e.what());
                throw;
            }

            try
            {
                oxenc::bt_dict_consumer btdc{payload};

                NetworkAddress initiator;
                RouterID init_rid;
                HopID remote_pivot_txid;
                HopID local_pivot_txid;
                bool use_tun;
                std::optional<std::string> maybe_auth = std::nullopt;

                init_rid.from_string(btdc.require<std::string_view>("i"));
                initiator = NetworkAddress::from_pubkey(init_rid, true);
                remote_pivot_txid.from_string(btdc.require<std::string_view>("p"));
                local_pivot_txid.from_string(btdc.require<std::string_view>("r"));
                use_tun = btdc.require<bool>("t");
                maybe_auth = btdc.maybe<std::string>("u");

                return {
                    std::move(kx_data),
                    std::move(initiator),
                    std::move(local_pivot_txid),
                    std::move(remote_pivot_txid),
                    use_tun,
                    std::move(maybe_auth)};
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught decrypting session initiation message:{}", e.what());
                throw;
            }
        }

        inline static std::string serialize_response(session_tag& t)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("t", t.view());
            return std::move(btdp).str();
        }

        inline static session_tag deserialize_response(oxenc::bt_dict_consumer&& btdc)
        {
            try
            {
                session_tag tag;
                tag.read(btdc.require<std::string_view>("t"));
                return tag;
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing session initiation response:{}", e.what());
                throw;
            }
        }

    }  // namespace InitiateSession

    /** Fields for setting a session tag:
     */
    namespace SetSessionTag
    {
        inline static std::string serialize()
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                //
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: SetSessionTagMessage failed to bt encode contents");
            }

            return std::move(btdp).str();
        };
    }  // namespace SetSessionTag

    /** Fields for setting a session path:
     */
    namespace SetSessionPath
    {
        inline static std::string serialize()
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                //
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: SetSessionPathMessage failed to bt encode contents");
            }

            return std::move(btdp).str();
        };
    }  // namespace SetSessionPath

}  // namespace llarp
