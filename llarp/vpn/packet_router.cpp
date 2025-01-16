#include "packet_router.hpp"

#include <llarp/util/logging.hpp>

namespace llarp::vpn
{
    static auto logcat = log::Cat("packet_router");

    struct UDPPacketHandler : public Layer4Handler
    {
        ip_pkt_hook _base_handler;
        std::unordered_map<uint16_t, ip_pkt_hook> _port_mapped_handlers;

        explicit UDPPacketHandler(ip_pkt_hook baseHandler) : _base_handler{std::move(baseHandler)} {}

        void add_sub_handler(uint16_t localport, ip_pkt_hook handler) override
        {
            _port_mapped_handlers.emplace(localport, std::move(handler));
            log::debug(logcat, "UDP packet sub-handler registered for local port {}", localport);
        }

        void handle_ip_packet(IPPacket pkt) override
        {
            log::trace(logcat, "udp pkt: ", pkt.info_line());
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

        void handle_ip_packet(IPPacket pkt) override
        {
            log::critical(logcat, "(FIXME) l4 pkt: {}", pkt.info_line());
            // TOFIX:
            // _base_handler(IPPacket::from_udp(std::move(pkt)));
        }
    };

    PacketRouter::PacketRouter(ip_pkt_hook baseHandler) : _handler{std::move(baseHandler)} {}

    void PacketRouter::handle_ip_packet(IPPacket pkt) const
    {
        if (pkt.is_ipv4())
            log::trace(logcat, "ipv4 pkt: {}", pkt.info_line());
        auto dest_port = pkt.dest_port();

        if (not dest_port)
            return _handler(std::move(pkt));

        auto proto = pkt.protocol();
        if (auto itr = _ip_proto_handler.find(proto); itr != _ip_proto_handler.end())
            itr->second->handle_ip_packet(std::move(pkt));
        else
            _handler(std::move(pkt));
    }

    void PacketRouter::add_udp_handler(uint16_t localport, ip_pkt_hook func)
    {
        auto [it, b] = _ip_proto_handler.try_emplace(net::IPProtocol::UDP, nullptr);

        if (b)
            it->second = std::make_unique<UDPPacketHandler>(_handler);
        else
            log::info(logcat, "Packet router already holds registered UDP packet handler!");

        it->second->add_sub_handler(localport, std::move(func));
    }

    void PacketRouter::add_ip_proto_handler(net::IPProtocol proto, ip_pkt_hook func)
    {
        _ip_proto_handler[proto] = std::make_unique<GenericLayer4Handler>(std::move(func));
    }

}  // namespace llarp::vpn
