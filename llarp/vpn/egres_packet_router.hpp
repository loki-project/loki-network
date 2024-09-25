#pragma once

#include <llarp/address/address.hpp>
#include <llarp/address/ip_packet.hpp>
#include <llarp/net/net_int.hpp>

#include <functional>
#include <unordered_map>

namespace llarp::vpn
{
    using EgresPacketHandlerFunc = std::function<void(NetworkAddress, IPPacket)>;

    struct EgresLayer4Handler
    {
        virtual ~EgresLayer4Handler() = default;

        virtual void HandleIPPacketFrom(NetworkAddress from, IPPacket pkt) = 0;

        virtual void AddSubHandler(uint16_t, EgresPacketHandlerFunc){};
        virtual void RemoveSubHandler(uint16_t){};
    };

    class EgresPacketRouter
    {
        EgresPacketHandlerFunc _handler;
        std::unordered_map<uint8_t, std::unique_ptr<EgresLayer4Handler>> _proto_handlers;

      public:
        /// baseHandler will be called if no other handlers matches a packet
        explicit EgresPacketRouter(EgresPacketHandlerFunc baseHandler);

        /// feed in an ip packet for handling
        void HandleIPPacketFrom(NetworkAddress, IPPacket pkt);

        /// add a non udp packet handler using ip protocol proto
        void AddIProtoHandler(uint8_t proto, EgresPacketHandlerFunc func);

        /// helper that adds a udp packet handler for UDP destinted for localport
        void AddUDPHandler(uint16_t localport, EgresPacketHandlerFunc func);

        /// remove a udp handler that is already set up by bound port
        void RemoveUDPHandler(uint16_t localport);
    };
}  // namespace llarp::vpn
