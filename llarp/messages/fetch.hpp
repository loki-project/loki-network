#pragma once

#include "common.hpp"

#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    namespace GossipRCMessage
    {
        inline static std::string serialize(const RouterID& last_sender, const RemoteRC& rc)
        {
            oxenc::bt_dict_producer btdp;

            btdp.append_encoded("r", rc.view());
            btdp.append("s", last_sender.to_view());

            return std::move(btdp).str();
        }
    }  // namespace GossipRCMessage

    namespace BootstrapFetchMessage
    {
        // the LocalRC is converted to a RemoteRC type to send to the bootstrap seed
        inline static std::string serialize(std::optional<LocalRC> local_rc, size_t quantity)
        {
            oxenc::bt_dict_producer btdp;

            if (local_rc)
            {
                log::trace(messages::logcat, "Serializing localRC: {}", oxenc::to_hex(local_rc->view()));
                btdp.append_encoded("l", local_rc->view());
            }

            btdp.append("q", quantity);

            return std::move(btdp).str();
        }
    }  // namespace BootstrapFetchMessage

    namespace FetchRCMessage
    {
        inline const auto INVALID_REQUEST =
            messages::serialize_response({{messages::STATUS_KEY, "Invalid relay ID requested"}});

        inline static std::string serialize(const std::vector<RouterID>& explicit_ids)
        {
            oxenc::bt_dict_producer btdp;

            auto sublist = btdp.append_list("x");

            for (const auto& rid : explicit_ids)
                sublist.append(rid.to_view());

            return std::move(btdp).str();
        }
    }  // namespace FetchRCMessage

    namespace FetchRIDMessage
    {
        inline constexpr auto INVALID_REQUEST = "Invalid relay ID requested to relay response from."sv;

        inline static std::string serialize(const RouterID& source)
        {
            oxenc::bt_dict_producer btdp;
            btdp.append("s", source.to_view());
            return std::move(btdp).str();
        }
    }  // namespace FetchRIDMessage

}  // namespace llarp
