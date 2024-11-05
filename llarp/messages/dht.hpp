#pragma once

#include "common.hpp"

#include <llarp/contact/client_contact.hpp>
#include <llarp/contact/sns.hpp>

namespace llarp
{
    namespace PublishClientContact
    {
        inline const auto INVALID = messages::serialize_response({{messages::STATUS_KEY, "INVALID CC"}});
        inline const auto EXPIRED = messages::serialize_response({{messages::STATUS_KEY, "EXPIRED CC"}});
        inline const auto INSUFFICIENT = messages::serialize_response({{messages::STATUS_KEY, "INSUFFICIENT NODES"}});
        inline const auto INVALID_ORDER = messages::serialize_response({{messages::STATUS_KEY, "INVALID ORDER"}});

        /** Bt-encoded contents:
            - 'x' : EncryptedClientContact

            Note: we are bt-encoding to leave space for future fields (ex: version)
         */
        inline static std::string serialize(const EncryptedClientContact& ecc)
        {
            oxenc::bt_dict_producer btdp;

            btdp.append("x", ecc.bt_payload());

            return std::move(btdp).str();
        }

        inline static EncryptedClientContact deserialize(oxenc::bt_dict_consumer&& btdc)
        {
            EncryptedClientContact ecc;

            try
            {
                ecc = EncryptedClientContact::deserialize(btdc.require<std::string_view>("x"));
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error{"Exception caught deserializing EncryptedClientContact: {}"_format(e.what())};
            }

            return ecc;
        }
    }  // namespace PublishClientContact

    namespace FindClientContact
    {
        inline const auto NOT_FOUND = messages::serialize_response({{messages::STATUS_KEY, "NOT FOUND"}});
        inline const auto INSUFFICIENT = messages::serialize_response({{messages::STATUS_KEY, "INSUFFICIENT NODES"}});
        inline const auto INVALID_ORDER = messages::serialize_response({{messages::STATUS_KEY, "INVALID ORDER"}});

        /** Bt-encoded contents:
            - 'k' : DHT key corresponding to client contact

            Note: we are bt-encoding to leave space for future fields (ex: version)
         */
        inline static std::string serialize(const dht::Key_t& location)
        {
            oxenc::bt_dict_producer btdp;

            btdp.append("k", location.to_view());

            return std::move(btdp).str();
        }

        inline static dht::Key_t deserialize(oxenc::bt_dict_consumer&& btdc)
        {
            dht::Key_t key;

            try
            {
                key.from_string(btdc.require<std::string_view>("k"));
            }
            catch (const std::exception& e)
            {
                log::error(messages::logcat, "Error: failed to deserialize FindClientContact contents: {}", e.what());
                throw;
            }

            return key;
        }

        /** Bt-encoded contents:
            - 'x' : EncryptedClientContact

            Note: we are bt-encoding to leave space for future fields (ex: version)
         */
        inline static std::string serialize_response(const EncryptedClientContact& ecc)
        {
            oxenc::bt_dict_producer btdp;

            btdp.append("x", ecc.bt_payload());

            return std::move(btdp).str();
        }

        inline static EncryptedClientContact deserialize_response(oxenc::bt_dict_consumer&& btdc)
        {
            EncryptedClientContact ecc;

            try
            {
                ecc = EncryptedClientContact::deserialize(btdc.require<std::string_view>("x"));
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error{"Exception caught deserializing EncryptedClientContact: {}"_format(e.what())};
            }

            return ecc;
        }
    }  //  namespace FindClientContact

    namespace ResolveSNS
    {
        inline const auto NOT_FOUND = messages::serialize_response({{messages::STATUS_KEY, "NOT FOUND"}});

        /** Bt-encoded contents:
            - 's' : SNS name

            Note: we are bt-encoding to leave space for future fields (ex: version)
         */
        inline static std::string serialize(std::string_view name_hash)
        {
            oxenc::bt_dict_producer btdp;

            btdp.append("s", name_hash);

            return std::move(btdp).str();
        }

        inline static std::string deserialize(oxenc::bt_dict_consumer&& btdc)
        {
            try
            {
                return btdc.require<std::string>("s");
            }
            catch (const std::exception& e)
            {
                log::error(messages::logcat, "Error: failed to deserialize ResolveSNS contents: {}", e.what());
                throw;
            }
        }

        /** Bt-encoded contents:
            - 'x' : EncryptedSNSRecord

            Note: we are bt-encoding to leave space for future fields (ex: version)
         */
        inline static std::string serialize_response(const EncryptedSNSRecord& enc)
        {
            oxenc::bt_dict_producer btdp;

            btdp.append("x", enc.bt_payload());

            return std::move(btdp).str();
        }

        inline static EncryptedSNSRecord deserialize_response(oxenc::bt_dict_consumer&& btdc)
        {
            EncryptedSNSRecord enc{};

            try
            {
                enc = EncryptedSNSRecord::deserialize(btdc.require<std::string_view>("x"));
            }
            catch (const std::exception& e)
            {
                log::error(messages::logcat, "Error: failed to deserialize ResolveSNS contents: {}", e.what());
                throw;
            }

            return enc;
        }
    }  // namespace ResolveSNS

}  // namespace llarp
