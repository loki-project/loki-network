#pragma once
#include <llarp/endpoint_base.hpp>
#include <llarp/net/ip_packet_old.hpp>
#include <llarp/net/net_int.hpp>

#include <functional>
#include <unordered_map>

namespace llarp::vpn
{
    using EgresPacketHandlerFunc = std::function<void(AddressVariant_t, net::IP_packet_deprecated)>;

    struct EgresLayer4Handler
    {
        virtual ~EgresLayer4Handler() = default;

        virtual void HandleIPPacketFrom(AddressVariant_t from, net::IP_packet_deprecated pkt) = 0;

        virtual void AddSubHandler(nuint16_t, EgresPacketHandlerFunc){};
        virtual void RemoveSubHandler(nuint16_t){};
    };

    class EgresPacketRouter
    {
        EgresPacketHandlerFunc m_BaseHandler;
        std::unordered_map<uint8_t, std::unique_ptr<EgresLayer4Handler>> m_IPProtoHandler;

       public:
        /// baseHandler will be called if no other handlers matches a packet
        explicit EgresPacketRouter(EgresPacketHandlerFunc baseHandler);

        /// feed in an ip packet for handling
        void HandleIPPacketFrom(AddressVariant_t, net::IP_packet_deprecated pkt);

        /// add a non udp packet handler using ip protocol proto
        void AddIProtoHandler(uint8_t proto, EgresPacketHandlerFunc func);

        /// helper that adds a udp packet handler for UDP destinted for localport
        void AddUDPHandler(huint16_t localport, EgresPacketHandlerFunc func);

        /// remove a udp handler that is already set up by bound port
        void RemoveUDPHandler(huint16_t localport);
    };
}  // namespace llarp::vpn
