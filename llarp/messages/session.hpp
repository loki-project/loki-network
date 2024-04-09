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
            std::optional<std::string_view> auth_token)
        {
            try
            {
                std::string payload;

                {
                    oxenc::bt_dict_producer btdp;

                    btdp.append("i", local.to_view());
                    btdp.append("s", tag.to_view());
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

        inline static ustring deserialize_decrypt(oxenc::bt_dict_consumer& btdc, const RouterID& local)
        {
            try
            {
                SymmNonce nonce;
                RouterID shared_pubkey;
                ustring payload;

                nonce = SymmNonce::make(btdc.require<std::string>("n"));
                shared_pubkey = RouterID{btdc.require<std::string>("s")};
                payload = btdc.require<ustring>("x");

                crypto::derive_decrypt_outer_wrapping(local, shared_pubkey, nonce, payload);

                return payload;
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing onion data:{}", e.what());
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
