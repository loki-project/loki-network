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
            - 'p' : HopID at the pivot taken from remote ClientIntro
            - 's' : SessionTag for current session
            - 't' : Use Tun interface (bool)
            - 'u' : Authentication field
                - bt-encoded dict, values TBD
    */
    namespace InitiateSession
    {
        static auto logcat = llarp::log::Cat("session-init");

        inline const auto AUTH_ERROR = messages::serialize_response({{messages::STATUS_KEY, "AUTH ERROR"}});
        inline const auto BAD_PATH = messages::serialize_response({{messages::STATUS_KEY, "BAD PATH"}});

        inline static std::string serialize_encrypt(
            const RouterID& local,
            const RouterID& remote,
            SessionTag& tag,
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

                Ed25519SecretKey ephemeral_key;
                crypto::identity_keygen(ephemeral_key);

                SharedSecret shared;
                auto nonce = SymmNonce::make_random();

                crypto::derive_encrypt_outer_wrapping(ephemeral_key, shared, nonce, remote, to_uspan(payload));

                return ONION::serialize_hop(ephemeral_key.to_pubkey().to_view(), nonce, std::move(payload));
            }
            catch (const std::exception& e)
            {
                log::error(messages::logcat, "Exception caught encrypting session initiation message: {}", e.what());
                throw;
            }
        };

        inline static std::tuple<NetworkAddress, HopID, SessionTag, bool, std::optional<std::string>>
        decrypt_deserialize(oxenc::bt_dict_consumer&& btdc, const Ed25519SecretKey& local)
        {
            SymmNonce nonce;
            PubKey shared_pubkey;
            std::string payload;
            SharedSecret shared;

            try
            {
                std::tie(shared_pubkey, nonce, payload) = ONION::deserialize(std::move(btdc));
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught deserializing hop dict: {}", e.what());
                throw;
            }

            try
            {
                crypto::derive_decrypt_outer_wrapping(local, shared, shared_pubkey, nonce, to_uspan(payload));

                {
                    NetworkAddress initiator;
                    SessionTag tag;
                    HopID pivot_txid;
                    bool use_tun;
                    std::optional<std::string> maybe_auth = std::nullopt;

                    if (auto maybe_remote = NetworkAddress::from_network_addr(btdc.require<std::string_view>("i")))
                        initiator = *maybe_remote;
                    else
                        throw std::runtime_error{"Invalid NetworkAddress!"};

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
