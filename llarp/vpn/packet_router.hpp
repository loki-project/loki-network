#pragma once
#include <llarp/net/ip_packet.hpp>
#include <llarp/net/net_int.hpp>

#include <functional>
#include <unordered_map>

namespace llarp::vpn
{
    using PacketHandlerFunc_t = std::function<void(llarp::net::IP_packet_deprecated)>;

    struct Layer4Handler;

    class PacketRouter
    {
        PacketHandlerFunc_t m_BaseHandler;
        std::unordered_map<uint8_t, std::unique_ptr<Layer4Handler>> m_IPProtoHandler;

       public:
        /// baseHandler will be called if no other handlers matches a packet
        explicit PacketRouter(PacketHandlerFunc_t baseHandler);

        /// feed in an ip packet for handling
        void HandleIPPacket(llarp::net::IP_packet_deprecated pkt);

        /// add a non udp packet handler using ip protocol proto
        void AddIProtoHandler(uint8_t proto, PacketHandlerFunc_t func);

        /// helper that adds a udp packet handler for UDP destinted for localport
        void AddUDPHandler(huint16_t localport, PacketHandlerFunc_t func);

        /// remove a udp handler that is already set up by bound port
        void RemoveUDPHandler(huint16_t localport);
    };

    struct Layer4Handler
    {
        virtual ~Layer4Handler() = default;

        virtual void HandleIPPacket(llarp::net::IP_packet_deprecated pkt) = 0;

        virtual void AddSubHandler(nuint16_t, PacketHandlerFunc_t){};
    };

}  // namespace llarp::vpn
