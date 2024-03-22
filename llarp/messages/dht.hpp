#pragma once

#include "common.hpp"

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
                btdp.append("S", location.ToView());
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

    namespace PublishIntroMessage
    {
        inline constexpr auto INVALID_INTROSET = "INVALID INTROSET"sv;
        inline constexpr auto EXPIRED = "EXPIRED INTROSET"sv;
        inline constexpr auto INSUFFICIENT = "INSUFFICIENT NODES"sv;
        inline constexpr auto INVALID_ORDER = "INVALID ORDER"sv;

        inline static std::string serialize(std::string introset, uint64_t relay_order, uint64_t is_relayed)
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                btdp.append("I", introset);
                btdp.append("O", relay_order);
                btdp.append("R", is_relayed);
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: FindNameMessage failed to bt encode contents!");
            }

            return std::move(btdp).str();
        }
    }  // namespace PublishIntroMessage
}  // namespace llarp
