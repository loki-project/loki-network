#include "packet_router.hpp"

namespace llarp::vpn
{
    struct UDPPacketHandler : public Layer4Handler
    {
        ip_pkt_hook _base_handler;
        std::unordered_map<uint16_t, ip_pkt_hook> _port_mapped_handlers;

        explicit UDPPacketHandler(ip_pkt_hook baseHandler) : _base_handler{std::move(baseHandler)} {}

        void add_sub_handler(uint16_t localport, ip_pkt_hook handler) override
        {
            _port_mapped_handlers.emplace(localport, std::move(handler));
        }

        void handle_ip_packet(IPPacket pkt) override
        {
            auto dstport = pkt.dest_port();

            if (not dstport)
            {
                // TOFIX:
                // _base_handler(IPPacket::from_udp(std::move(pkt)));
                return;
            }

            if (auto itr = _port_mapped_handlers.find(dstport); itr != _port_mapped_handlers.end())
                itr->second(std::move(pkt));
            // else
            //     _base_handler(IPPacket::from_udp(std::move(pkt)));
        }
    };

    struct GenericLayer4Handler : public Layer4Handler
    {
        ip_pkt_hook _base_handler;

        explicit GenericLayer4Handler(ip_pkt_hook baseHandler) : _base_handler{std::move(baseHandler)} {}

        void handle_ip_packet(IPPacket) override
        {
            // TOFIX:
            // _base_handler(IPPacket::from_udp(std::move(pkt)));
        }
    };

    PacketRouter::PacketRouter(ip_pkt_hook baseHandler) : _handler{std::move(baseHandler)} {}

    void PacketRouter::handle_ip_packet(IPPacket pkt)
    {
        auto dest_port = pkt.dest_port();

        if (not dest_port)
            return _handler(std::move(pkt));

        auto proto = pkt.protocol();
        if (const auto itr = _ip_proto_handler.find(*proto); itr != _ip_proto_handler.end())
            itr->second->handle_ip_packet(std::move(pkt));
        else
            _handler(std::move(pkt));
    }

    void PacketRouter::add_udp_handler(uint16_t localport, ip_pkt_hook func)
    {
        constexpr uint8_t udp_proto = 0x11;

        if (_ip_proto_handler.find(udp_proto) == _ip_proto_handler.end())
        {
            _ip_proto_handler.emplace(udp_proto, std::make_unique<UDPPacketHandler>(_handler));
        }
        _ip_proto_handler[udp_proto]->add_sub_handler(localport, func);
    }

    void PacketRouter::add_ip_proto_handler(uint8_t proto, ip_pkt_hook func)
    {
        _ip_proto_handler[proto] = std::make_unique<GenericLayer4Handler>(std::move(func));
    }

}  // namespace llarp::vpn
