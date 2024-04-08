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
        inline static std::string serialize(
            RouterID local, RouterID remote, service::SessionTag tag, std::shared_ptr<auth::SessionAuthPolicy>& auth)
        {
            try
            {
                std::string payload;

                {
                    oxenc::bt_dict_producer btdp;

                    btdp.append("i", local.to_view());
                    btdp.append("s", tag.to_view());
                    // DISCUSS: this auth field
                    if (auto token = auth->fetch_auth_token())
                        btdp.append("u", *token);

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
