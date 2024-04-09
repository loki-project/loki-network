#include "egres_packet_router.hpp"

namespace llarp::vpn
{
    struct EgresUDPPacketHandler : public EgresLayer4Handler
    {
        EgresPacketHandlerFunc _handler;
        std::unordered_map<uint16_t, EgresPacketHandlerFunc> _ports;

        explicit EgresUDPPacketHandler(EgresPacketHandlerFunc baseHandler) : _handler{std::move(baseHandler)}
        {}

        void AddSubHandler(uint16_t localport, EgresPacketHandlerFunc handler) override
        {
            _ports.emplace(std::move(localport), std::move(handler));
        }

        void RemoveSubHandler(uint16_t localport) override
        {
            _ports.erase(localport);
        }

        void HandleIPPacketFrom(NetworkAddress from, IPPacket pkt) override
        {
            (void)from;
            (void)pkt;
            // TOFIX:
            // auto ip_pkt = IPPacket::from_udp(std::move(pkt));

            // if (auto dstPort = pkt.path.remote.port())
            // {
            //     if (auto itr = _ports.find(dstPort); itr != _ports.end())
            //     {
            //         itr->second(std::move(from), std::move(ip_pkt));
            //         return;
            //     }
            // }
            // _handler(std::move(from), std::move(ip_pkt));
        }
    };

    struct EgresGenericLayer4Handler : public EgresLayer4Handler
    {
        EgresPacketHandlerFunc _handler;

        explicit EgresGenericLayer4Handler(EgresPacketHandlerFunc baseHandler) : _handler{std::move(baseHandler)}
        {}

        void HandleIPPacketFrom(NetworkAddress from, IPPacket pkt) override
        {
            // TOFIX: this
            (void)from;
            (void)pkt;
            // _handler(std::move(from), IPPacket::from_udp(std::move(pkt)));
        }
    };

    EgresPacketRouter::EgresPacketRouter(EgresPacketHandlerFunc baseHandler) : _handler{std::move(baseHandler)}
    {}

    void EgresPacketRouter::HandleIPPacketFrom(NetworkAddress from, IPPacket pkt)
    {
        (void)from;
        (void)pkt;
        // const auto proto = pkt.Header()->protocol;
        // if (const auto itr = _proto_handlers.find(proto); itr != _proto_handlers.end())
        // {
        //     itr->second->HandleIPPacketFrom(std::move(from), std::move(pkt));
        // }
        // else
        // TOFIX:
        // _handler(std::move(from), IPPacket::from_udp(std::move(pkt)));
    }

    namespace
    {
        constexpr uint8_t udp_proto = 0x11;
    }

    void EgresPacketRouter::AddUDPHandler(uint16_t localport, EgresPacketHandlerFunc func)
    {
        if (_proto_handlers.find(udp_proto) == _proto_handlers.end())
        {
            _proto_handlers.emplace(udp_proto, std::make_unique<EgresUDPPacketHandler>(_handler));
        }
        _proto_handlers[udp_proto]->AddSubHandler(localport, std::move(func));
    }

    void EgresPacketRouter::AddIProtoHandler(uint8_t proto, EgresPacketHandlerFunc func)
    {
        _proto_handlers[proto] = std::make_unique<EgresGenericLayer4Handler>(std::move(func));
    }

    void EgresPacketRouter::RemoveUDPHandler(uint16_t localport)
    {
        if (auto itr = _proto_handlers.find(udp_proto); itr != _proto_handlers.end())
        {
            itr->second->RemoveSubHandler(localport);
        }
    }

}  // namespace llarp::vpn
