#pragma once

#include "rpc_request_decorators.hpp"

#include <llarp/address/ip_range.hpp>
#include <llarp/config/config.hpp>
#include <llarp/router/route_poker.hpp>
#include <llarp/service/address.hpp>
#include <llarp/service/endpoint.hpp>

#include <oxen/log/omq_logger.hpp>
#include <oxenmq/address.h>
#include <oxenmq/oxenmq.h>

#include <string_view>
#include <unordered_map>
#include <vector>

namespace llarp::rpc
{
    //  RPC: halt
    //    Stops lokinet router
    //
    //  Inputs: none
    //
    struct Halt : NoArgs, Immediate
    {
        static constexpr auto name = "halt"sv;
    };

    //  RPC: version
    //    Returns version and uptime information
    //
    //  Inputs: none
    //
    //  Returns: "OK"
    //    "uptime"
    //    "version"
    //
    struct Version : NoArgs, Immediate
    {
        static constexpr auto name = "version"sv;
    };

    //  RPC: status
    //    Returns that current activity status of lokinet router
    //    Calls router::extractstatus
    //
    //  Inputs: none
    //
    //  Returns: massive dump of status info including
    //    "running"
    //    "numNodesKnown"
    //    "dht"
    //    "services"
    //    "exit"
    //    "links"
    //    "outboundMessages"
    //    etc
    //
    struct Status : NoArgs
    {
        static constexpr auto name = "status"sv;
    };

    //  RPC: get_status
    //    Returns current summary status
    //
    //  Inputs: none
    //
    //  Returns: slightly smaller dump of status info including
    //    "authcodes"
    //    "exitMap"
    //    "lokiAddress"
    //    "networkReady"
    //    "numPathsBuilt"
    //    "numPeersConnected"
    //    etc
    //
    struct GetStatus : NoArgs
    {
        static constexpr auto name = "get_status"sv;
    };

    //  RPC: quic_connect
    //    Initializes QUIC connection tunnel
    //    Passes request parameters in nlohmann::json format
    //
    //  Inputs:
    //    "endpoint" : endpoint id (string)
    //    "bindAddr" : bind address (string, ex: "127.0.0.1:1142")
    //    "host" : remote host ID (string)
    //    "port" : port to bind to (int)
    //    "close" : close connection to port or host ID
    //
    //  Returns:
    //    "id" : connection ID
    //    "addr" : connection local address
    //
    struct QuicConnect : RPCRequest
    {
        static constexpr auto name = "quic_connect"sv;

        struct request_parameters
        {
            std::string bindAddr;
            int closeID;
            std::string endpoint;
            uint16_t port;
            std::string remoteHost;
        } request;
    };

    //  RPC: quic_listener
    //    Connects to QUIC interface on local endpoint
    //    Passes request parameters in nlohmann::json format
    //
    //  Inputs:
    //    "endpoint" : endpoint id (string)
    //    "host" : remote host ID (string)
    //    "port" : port to bind to (int)
    //    "close" : close connection to port or host ID
    //    "srv-proto" :
    //
    //  Returns:
    //    "id" : connection ID
    //    "addr" : connection local address
    //
    struct QuicListener : RPCRequest
    {
        static constexpr auto name = "quic_listener"sv;

        struct request_parameters
        {
            int closeID;
            std::string endpoint;
            uint16_t port;
            std::string remoteHost;
            std::string srvProto;
        } request;
    };

    //  RPC: lookup_snode
    //    Look up service node
    //    Passes request parameters in nlohmann::json format
    //
    //  Inputs:
    //    "routerID" : router ID to query (string)
    //
    //  Returns:
    //    "ip" : snode IP address
    //
    struct LookupSnode : RPCRequest
    {
        static constexpr auto name = "lookup_snode"sv;

        struct request_parameters
        {
            std::string routerID;
        } request;
    };

    //  RPC: map_exit
    //    Map a new connection to an exit node
    //
    //  Inputs:
    //    "address" : ID of endpoint to map
    //    "range" : IP range to map to exit node
    //    "token" : auth token
    //
    //  Returns:
    //
    struct MapExit : RPCRequest
    {
        MapExit()
        {
            if constexpr (platform::supports_ipv6)
                request.ip_range.emplace_back("::"s, 0);
            else
                request.ip_range.emplace_back("0.0.0.0"s, 0);
        }

        static constexpr auto name = "map_exit"sv;

        struct request_parameters
        {
            std::string address;
            std::vector<IPRange> ip_range;
            std::string token;
        } request;
    };

    //  RPC: list_exits
    //    List all currently mapped exit node connections
    //
    //  Inputs: none
    //
    //  Returns:
    //
    struct ListExits : NoArgs
    {
        static constexpr auto name = "list_exits"sv;
    };

    //  RPC: unmap_exit
    //    Unmap a connection to an exit node
    //
    //  Inputs:
    //    "endpoint" : ID of endpoint to map
    //    "range" : IP range to map to exit node
    //    "token" : auth token
    //
    //  Returns:
    //
    struct UnmapExit : RPCRequest
    {
        UnmapExit()
        {
            if constexpr (platform::supports_ipv6)
                request.ip_range.emplace_back("::", 0);
            else
                request.ip_range.emplace_back("0.0.0.0", 0);
        }

        static constexpr auto name = "unmap_exit"sv;

        struct request_parameters
        {
            std::vector<IPRange> ip_range;
        } request;
    };

    //  RPC: swap_exit
    //    Swap a connection from one exit to another
    //
    //  Inputs:
    //    "exits" : exit nodes to swap mappings from (index 0 = old exit, index 1 = new exit)
    //
    //  Returns:
    //
    struct SwapExits : RPCRequest
    {
        static constexpr auto name = "swap_exits"sv;

        struct request_parameters
        {
            std::vector<std::string> exit_addresses;
            std::string token;
        } request;
    };

    //  RPC: dns_query
    //    Attempts to query endpoint by domain name
    //
    //  Inputs:
    //    "endpoint" : endpoint ID to query (string)
    //    "qname" : query name (string)
    //    "qtype" : query type (int)
    //
    //  Returns:
    //
    struct DNSQuery : Immediate
    {
        static constexpr auto name = "dns_query"sv;

        struct request_parameters
        {
            std::string endpoint;
            uint16_t qtype;
            std::string qname;
        } request;
    };

    //  RPC: config
    //    Runs lokinet router using .ini config file passed as path
    //
    //  Inputs:
    //    "filename" : name of .ini file to either save or delete
    //    "ini" : .ini chunk to save in new file
    //    "del" : boolean specifying whether to delete file "filename" or save it
    //
    //  Returns:
    //
    struct Config : Immediate
    {
        static constexpr auto name = "config"sv;

        struct request_parameters
        {
            bool del;
            std::string filename;
            std::string ini;
        } request;
    };

    // List of all RPC request structs to allow compile-time enumeration of all supported types
    using rpc_request_types = tools::type_list<
        Halt,
        Version,
        Status,
        GetStatus,
        QuicConnect,
        QuicListener,
        LookupSnode,
        MapExit,
        ListExits,
        SwapExits,
        UnmapExit,
        DNSQuery,
        Config>;

}  // namespace llarp::rpc
