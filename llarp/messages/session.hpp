#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    /** Fields for initiating sessions:
        - 'n' : symmetric nonce
        - 's' : shared pubkey used to derive symmetric key
        - 'x' : encrypted payload
            - 'i' : RouterID of initiator
            - 's' : SessionTag for current session
            - 't' : Terminal hop TXID of newly constructed path
            - 'u' : Authentication field
                - bt-encoded dict, values TBD
    */
    namespace InitiateSession
    {
        static auto logcat = llarp::log::Cat("session-init");

        inline static std::string serialize_encrypt(
            const RouterID& local,
            const RouterID& remote,
            service::SessionTag& tag,
            HopID terminal_txid,
            std::optional<std::string_view> auth_token)
        {
            try
            {
                std::string payload;

                {
                    oxenc::bt_dict_producer btdp;

                    btdp.append("i", local.to_view());
                    btdp.append("s", tag.to_view());
                    btdp.append("t", terminal_txid.to_view());
                    // DISCUSS: this auth field
                    if (auth_token)
                        btdp.append("u", *auth_token);

                    payload = std::move(btdp).str();
                }

                SecretKey shared_key;
                crypto::encryption_keygen(shared_key);

                SharedSecret shared;
                auto nonce = SymmNonce::make_random();

                crypto::derive_encrypt_outer_wrapping(shared_key, shared, nonce, remote, to_usv(payload));

                oxenc::bt_dict_producer btdp;

                btdp.append("n", nonce.to_view());
                btdp.append("s", shared_key.to_pubkey().to_view());
                btdp.append("x", payload);

                return std::move(btdp).str();
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: InitiateSessionMessage failed to bt encode contents");
                throw;
            }
        };

        inline static ustring decrypt(oxenc::bt_dict_consumer& btdc, const RouterID& local)
        {
            SymmNonce nonce;
            RouterID shared_pubkey;
            ustring payload;

            try
            {
                nonce = SymmNonce::make(btdc.require<std::string>("n"));
                shared_pubkey = RouterID{btdc.require<std::string>("s")};
                payload = btdc.require<ustring>("x");

                crypto::derive_decrypt_outer_wrapping(local, shared_pubkey, nonce, payload);
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught decrypting session initiation message:{}", e.what());
                throw;
            }

            return payload;
        }

        inline static std::tuple<RouterID, service::SessionTag, HopID, std::optional<std::string>> deserialize(
            oxenc::bt_dict_consumer& btdc)
        {
            RouterID initiator;
            service::SessionTag tag;
            HopID terminal_txid;
            std::optional<std::string> maybe_auth = std::nullopt;

            try
            {
                initiator.from_string(btdc.require<std::string_view>("i"));
                tag.from_string(btdc.require<std::string_view>("s"));
                terminal_txid.from_string(btdc.require<std::string_view>("t"));
                maybe_auth = btdc.maybe<std::string>("u");
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing session initiation payload:{}", e.what());
                throw;
            }

            return {std::move(initiator), std::move(tag), std::move(terminal_txid), std::move(maybe_auth)};
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
