#include "rpc_request_parser.hpp"

#include "param_parser.hpp"

namespace llarp::rpc
{
    using nlohmann::json;

    void parse_request(QuicConnect& quicconnect, rpc_input input)
    {
        get_values(
            input,
            "bindAddr",
            quicconnect.request.bindAddr,
            "closeID",
            quicconnect.request.closeID,
            "endpoint",
            quicconnect.request.endpoint,
            "port",
            quicconnect.request.port,
            "remoteHost",
            quicconnect.request.remoteHost);
    }

    void parse_request(QuicListener& quiclistener, rpc_input input)
    {
        get_values(
            input,
            "closeID",
            quiclistener.request.closeID,
            "endpoint",
            quiclistener.request.endpoint,
            "port",
            quiclistener.request.port,
            "remoteHost",
            quiclistener.request.remoteHost,
            "srvProto",
            quiclistener.request.srvProto);
    }

    void parse_request(FindCC& findcc, rpc_input input) { get_values(input, "pk", findcc.request.pk); }

    void parse_request(SessionInit& sessioninit, rpc_input input) { get_values(input, "pk", sessioninit.request.pk); }

    void parse_request(LookupSnode& lookupsnode, rpc_input input)
    {
        get_values(input, "routerID", lookupsnode.request.routerID);
    }

    void parse_request(MapExit& mapexit, rpc_input input)
    {
        get_values(
            input,
            "address",
            mapexit.request.address,
            "ip_range",
            mapexit.request.ip_range,
            "token",
            mapexit.request.token);
    }

    void parse_request(UnmapExit& unmapexit, rpc_input input)
    {
        get_values(input, "ip_range", unmapexit.request.ip_range);
    }

    void parse_request(SwapExits& swapexits, rpc_input input)
    {
        get_values(input, "exit_addresses", swapexits.request.exit_addresses, "token", swapexits.request.token);
    }

    void parse_request(DNSQuery& dnsquery, rpc_input input)
    {
        get_values(
            input,
            "endpoint",
            dnsquery.request.endpoint,
            "qname",
            dnsquery.request.qname,
            "qtype",
            dnsquery.request.qtype);
    }

    void parse_request(Config& config, rpc_input input)
    {
        get_values(input, "delete", config.request.del, "filename", config.request.filename, "ini", config.request.ini);
    }

}  // namespace llarp::rpc
