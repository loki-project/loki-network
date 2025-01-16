#pragma once

#include "rpc_request_definitions.hpp"

#include <llarp/config/config.hpp>

#include <oxenmq/address.h>
#include <oxenmq/oxenmq.h>

#include <string_view>

namespace llarp::rpc
{
    using rpc_input = std::variant<std::monostate, nlohmann::json, oxenc::bt_dict_consumer>;

    inline void parse_request(NoArgs&, rpc_input) {}

    void parse_request(QuicConnect& quicconnect, rpc_input input);
    void parse_request(QuicListener& quiclistener, rpc_input input);
    void parse_request(FindCC& findcc, rpc_input input);
    void parse_request(LookupSnode& lookupsnode, rpc_input input);
    void parse_request(MapExit& mapexit, rpc_input input);
    void parse_request(UnmapExit& unmapexit, rpc_input input);
    void parse_request(SwapExits& swapexits, rpc_input input);
    void parse_request(DNSQuery& dnsquery, rpc_input input);
    void parse_request(Config& config, rpc_input input);

}  // namespace llarp::rpc
