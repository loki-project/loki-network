#pragma once

#include <llarp/net/ip_packet.hpp>

#include <functional>
#include <unordered_map>

namespace llarp::vpn
{
    struct Layer4Handler;

    class PacketRouter
    {
        ip_pkt_hook _handler;
        // std::unordered_map<uint8_t, std::unique_ptr<Layer4Handler>> _ip_proto_handler;
        std::unordered_map<net::IPProtocol, std::unique_ptr<Layer4Handler>> _ip_proto_handler;

      public:
        /// baseHandler will be called if no other handlers matches a packet
        explicit PacketRouter(ip_pkt_hook baseHandler);

        /// feed in an ip packet for handling
        void handle_ip_packet(IPPacket pkt) const;

        /// add a non udp packet handler using ip protocol proto
        void add_ip_proto_handler(net::IPProtocol proto, ip_pkt_hook func);

        /// helper that adds a udp packet handler for UDP destined for localport
        void add_udp_handler(uint16_t port, ip_pkt_hook func);

        /// remove a udp handler that is already set up by bound port
        void remove_udp_handler(uint16_t port);
    };

    struct Layer4Handler
    {
        virtual ~Layer4Handler() = default;

        virtual void handle_ip_packet(IPPacket pkt) = 0;

        virtual void add_sub_handler(uint16_t, ip_pkt_hook){};
    };

}  // namespace llarp::vpn
