#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    /** Fields for initiating sessions:
        - 'd' : data
            - 'n' : symmetric nonce
            - 's' : shared key used to derive symmetric key
            - 'x' : encrypted payload
                - 'i' : RouterID of initiator
                - 's' : SessionTag for current session
                - 'u' : Authentication field
                    - bt-encoded dict, values TBD
        - 'h' : hash of dict 'd'
    */
    namespace InitiateSession
    {
        inline static std::string serialize(RouterID local, RouterID remote, service::SessionTag tag)
        {
            try
            {
                std::string payload;

                {
                    oxenc::bt_dict_producer btdp;

                    btdp.append("i", local.to_view());
                    btdp.append("s", tag.to_view());
                    // DISCUSS: this auth field
                    btdp.append("u", "");

                    payload = std::move(btdp).str();
                }

                SecretKey shared_key;
                crypto::encryption_keygen(shared_key);

                SharedSecret shared;
                SymmNonce nonce;
                nonce.Randomize();

                // derive (outer) shared key
                if (!crypto::dh_client(shared, remote, shared_key, nonce))
                {
                    auto err = "DH client failed during session initiation!"s;
                    log::warning(messages::logcat, "{}", err);
                    throw std::runtime_error{"err"};
                }

                // encrypt hop_info (mutates in-place)
                if (!crypto::xchacha20(reinterpret_cast<unsigned char*>(payload.data()), payload.size(), shared, nonce))
                {
                    auto err = "Session initiation payload encryption failed!"s;
                    log::warning(messages::logcat, "{}", err);
                    throw std::runtime_error{err};
                }

                std::string data;

                {
                    oxenc::bt_dict_producer btdp;

                    btdp.append("n", nonce.to_view());
                    btdp.append("s", shared_key.to_view());
                    btdp.append("x", payload);

                    data = std::move(btdp).str();
                }

                std::string hash;
                hash.reserve(SHORTHASHSIZE);

                if (!crypto::hmac(
                        reinterpret_cast<uint8_t*>(hash.data()),
                        reinterpret_cast<uint8_t*>(data.data()),
                        data.size(),
                        shared))
                {
                    auto err = "Failed to generate HMAC for Session initiation payload!"s;
                    log::warning(messages::logcat, "{}", err);
                    throw std::runtime_error{err};
                }

                oxenc::bt_dict_producer btdp;

                btdp.append("d", data);
                btdp.append("h", hash);

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
