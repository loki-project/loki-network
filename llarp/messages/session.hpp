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
            - 'p' : HopID at the pivot node of the newly constructed path
            - 's' : SessionTag for current session
            - 't' : Use Tun interface (bool)
            - 'u' : Authentication field
                - bt-encoded dict, values TBD
    */
    namespace InitiateSession
    {
        static auto logcat = llarp::log::Cat("session-init");

        inline constexpr auto auth_denied = "AUTH_DENIED"sv;

        inline const auto AUTH_DENIED = messages::serialize_response({{messages::STATUS_KEY, auth_denied}});

        inline static std::string serialize_encrypt(
            const RouterID& local,
            const RouterID& remote,
            service::SessionTag& tag,
            HopID pivot_txid,
            std::optional<std::string_view> auth_token,
            bool use_tun)
        {
            try
            {
                std::string payload;

                {
                    oxenc::bt_dict_producer btdp;

                    btdp.append("i", local.to_view());
                    btdp.append("p", pivot_txid.to_view());
                    btdp.append("s", tag.to_view());
                    btdp.append("t", use_tun);
                    // DISCUSS: this auth field
                    if (auth_token)
                        btdp.append("u", *auth_token);

                    payload = std::move(btdp).str();
                }

                Ed25519SecretKey shared_key;
                crypto::encryption_keygen(shared_key);

                SharedSecret shared;
                auto nonce = SymmNonce::make_random();

                crypto::derive_encrypt_outer_wrapping(shared_key, shared, nonce, remote, to_uspan(payload));

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

        inline static std::tuple<NetworkAddress, HopID, service::SessionTag, bool, std::optional<std::string>>
        decrypt_deserialize(oxenc::bt_dict_consumer& btdc, const Ed25519SecretKey& local)
        {
            SymmNonce nonce;
            RouterID shared_pubkey;
            ustring payload;

            try
            {
                nonce = SymmNonce::make(btdc.require<std::string>("n"));
                shared_pubkey = RouterID{btdc.require<std::string>("s")};
                payload = btdc.require<ustring>("x");

                crypto::derive_decrypt_outer_wrapping(local, shared_pubkey, nonce, to_uspan(payload));

                {
                    RouterID remote;
                    service::SessionTag tag;
                    HopID pivot_txid;
                    bool use_tun;
                    std::optional<std::string> maybe_auth = std::nullopt;

                    remote.from_string(btdc.require<std::string_view>("i"));
                    auto initiator = NetworkAddress::from_pubkey(remote, true);
                    pivot_txid.from_string(btdc.require<std::string_view>("p"));
                    tag.from_string(btdc.require<std::string_view>("s"));
                    use_tun = btdc.require<bool>("t");
                    maybe_auth = btdc.maybe<std::string>("u");

                    return {
                        std::move(initiator), std::move(pivot_txid), std::move(tag), use_tun, std::move(maybe_auth)};
                }
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught decrypting session initiation message:{}", e.what());
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
