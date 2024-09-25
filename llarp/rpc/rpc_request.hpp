#pragma once

#include "json_bt.hpp"
#include "rpc_request_decorators.hpp"
#include "rpc_request_definitions.hpp"
#include "rpc_request_parser.hpp"
#include "rpc_server.hpp"

#include <llarp/config/config.hpp>
#include <llarp/router/router.hpp>

#include <oxen/log/omq_logger.hpp>
#include <oxenmq/address.h>
#include <oxenmq/oxenmq.h>

#include <string_view>

namespace llarp::rpc
{
    using nlohmann::json;

    template <typename RPC>
    auto make_invoke()
    {
        return [](oxenmq::Message& m, RPCServer& server) {
            EndpointHandler<RPC> handler{server, m.send_later()};
            auto& rpc = handler.rpc;

            if (m.data.size() > 1)
            {
                m.send_reply(nlohmann::json{
                    {"error",
                     "Bad Request: RPC requests must have at most one data part (received {})"_format(m.data.size())}}
                                 .dump());
                return;
            }
            // parsing input as bt or json
            //    hand off to parse_request (overloaded versions)
            try
            {
                if (m.data.empty() or m.data[0].empty())
                {
                    parse_request(rpc, nlohmann::json::object());
                }
                else if (m.data[0].front() == 'd')
                {
                    rpc.set_bt();
                    parse_request(rpc, oxenc::bt_dict_consumer{m.data[0]});
                }
                else
                {
                    parse_request(rpc, nlohmann::json::parse(m.data[0]));
                }
            }
            catch (const std::exception& e)
            {
                m.send_reply(nlohmann::json{{"Failed to parse request parameters: "s + e.what()}}.dump());
                return;
            }

            if (not std::is_base_of_v<Immediate, RPC>)
            {
                server.m_Router.loop()->call_soon(std::move(handler));
            }
            else
            {
                handler();
            }
        };
    }

}  // namespace llarp::rpc
