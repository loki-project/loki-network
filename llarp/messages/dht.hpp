#pragma once

#include "common.hpp"

#include <llarp/contact/client_contact.hpp>

namespace llarp
{
    namespace FindIntroMessage
    {
        inline constexpr auto NOT_FOUND = "NOT FOUND"sv;
        inline constexpr auto INVALID_ORDER = "INVALID ORDER"sv;
        inline constexpr auto INSUFFICIENT_NODES = "INSUFFICIENT NODES"sv;

        inline static std::string serialize(const dht::Key_t& location, bool is_relayed, uint64_t order)
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                btdp.append("O", order);
                btdp.append("R", is_relayed ? 1 : 0);
                btdp.append("S", location.to_view());
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: FindIntroMessage failed to bt encode contents!");
            }

            return std::move(btdp).str();
        }
    }  // namespace FindIntroMessage

    namespace FindNameMessage
    {
        inline constexpr auto NOT_FOUND = "NOT FOUND"sv;

        inline static std::string serialize(std::string name_hash)
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                btdp.append("H", std::move(name_hash));
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: FindNameMessage failed to bt encode contents!");
            }

            return std::move(btdp).str();
        }

        inline static std::string serialize_response(std::string encrypted_name)
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                btdp.append("E", std::move(encrypted_name));
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: FindNameMessage failed to bt encode contents!");
            }

            return std::move(btdp).str();
        }
    }  // namespace FindNameMessage

    namespace FindClientContact
    {
        inline const auto NOT_FOUND = messages::serialize_response({{messages::STATUS_KEY, "NOT FOUND"}});
        inline const auto INSUFFICIENT = messages::serialize_response({{messages::STATUS_KEY, "INSUFFICIENT NODES"}});
        inline const auto INVALID_ORDER = messages::serialize_response({{messages::STATUS_KEY, "INVALID ORDER"}});

        inline static std::string serialize(const dht::Key_t& location, uint64_t relay_order, bool is_relayed)
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                btdp.append("k", location.to_view());
                btdp.append("o", relay_order);
                btdp.append("r", is_relayed);
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: failed to serialize PublishClientContact contents!");
            }

            return std::move(btdp).str();
        }

        inline static std::string serialize_response(std::string_view encrypted_payload)
        {
            return messages::serialize_response({{"ECC", encrypted_payload}});
        }

        inline static std::tuple<dht::Key_t, uint64_t, bool> deserialize(std::string_view buf)
        {
            dht::Key_t key;
            bool is_relayed;
            uint64_t relay_order;

            try
            {
                oxenc::bt_dict_consumer btdc{buf};
                key.from_string(btdc.require<std::string_view>("k"));
                is_relayed = btdc.require<bool>("o");
                relay_order = btdc.require<uint64_t>("r");
            }
            catch (const std::exception& e)
            {
                log::error(
                    messages::logcat, "Error: failed to deserialize PublishClientContact contents: {}", e.what());
                throw;
            }

            return {key, relay_order, is_relayed};
        }
    }  //  namespace FindClientContact

    namespace PublishClientContact
    {
        inline const auto SUCCESS = messages::serialize_response({{messages::STATUS_KEY, "SUCCESS"}});
        inline const auto INVALID = messages::serialize_response({{messages::STATUS_KEY, "INVALID CC"}});
        inline const auto EXPIRED = messages::serialize_response({{messages::STATUS_KEY, "EXPIRED CC"}});
        inline const auto INSUFFICIENT = messages::serialize_response({{messages::STATUS_KEY, "INSUFFICIENT NODES"}});
        inline const auto INVALID_ORDER = messages::serialize_response({{messages::STATUS_KEY, "INVALID ORDER"}});

        inline static std::string serialize(const EncryptedClientContact& ecc, uint64_t relay_order, bool is_relayed)
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                btdp.append("o", relay_order);
                btdp.append("r", is_relayed);
                btdp.append("x", ecc.bt_payload());
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: failed to serialize PublishClientContact contents!");
            }

            return std::move(btdp).str();
        }

        inline static std::tuple<EncryptedClientContact, uint64_t, bool> deserialize(std::string_view buf)
        {
            EncryptedClientContact ecc;
            bool is_relayed;
            uint64_t relay_order;

            try
            {
                oxenc::bt_dict_consumer btdc{buf};
                is_relayed = btdc.require<bool>("o");
                relay_order = btdc.require<uint64_t>("r");
                ecc = EncryptedClientContact::deserialize(btdc.require<std::string_view>("x"));
            }
            catch (const std::exception& e)
            {
                log::error(
                    messages::logcat, "Error: failed to deserialize PublishClientContact contents: {}", e.what());
                throw;
            }

            return {std::move(ecc), relay_order, is_relayed};
        }
    }  // namespace PublishClientContact
}  // namespace llarp
