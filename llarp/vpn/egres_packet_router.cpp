#include "egres_packet_router.hpp"

namespace llarp::vpn
{
    struct EgresUDPPacketHandler : public EgresLayer4Handler
    {
        EgresPacketHandlerFunc m_BaseHandler;
        std::unordered_map<nuint16_t, EgresPacketHandlerFunc> m_LocalPorts;

        explicit EgresUDPPacketHandler(EgresPacketHandlerFunc baseHandler) : m_BaseHandler{std::move(baseHandler)}
        {}

        void AddSubHandler(nuint16_t localport, EgresPacketHandlerFunc handler) override
        {
            m_LocalPorts.emplace(std::move(localport), std::move(handler));
        }

        void RemoveSubHandler(nuint16_t localport) override
        {
            m_LocalPorts.erase(localport);
        }

        void HandleIPPacketFrom(AddressVariant_t from, net::IPPacket pkt) override
        {
            if (auto dstPort = pkt.DstPort())
            {
                if (auto itr = m_LocalPorts.find(*dstPort); itr != m_LocalPorts.end())
                {
                    itr->second(std::move(from), std::move(pkt));
                    return;
                }
            }
            m_BaseHandler(std::move(from), std::move(pkt));
        }
    };

    struct EgresGenericLayer4Handler : public EgresLayer4Handler
    {
        EgresPacketHandlerFunc m_BaseHandler;

        explicit EgresGenericLayer4Handler(EgresPacketHandlerFunc baseHandler) : m_BaseHandler{std::move(baseHandler)}
        {}

        void HandleIPPacketFrom(AddressVariant_t from, net::IPPacket pkt) override
        {
            m_BaseHandler(std::move(from), std::move(pkt));
        }
    };

    EgresPacketRouter::EgresPacketRouter(EgresPacketHandlerFunc baseHandler) : m_BaseHandler{std::move(baseHandler)}
    {}

    void EgresPacketRouter::HandleIPPacketFrom(AddressVariant_t from, net::IPPacket pkt)
    {
        const auto proto = pkt.Header()->protocol;
        if (const auto itr = m_IPProtoHandler.find(proto); itr != m_IPProtoHandler.end())
        {
            itr->second->HandleIPPacketFrom(std::move(from), std::move(pkt));
        }
        else
            m_BaseHandler(std::move(from), std::move(pkt));
    }

    namespace
    {
        constexpr uint8_t udp_proto = 0x11;
    }

    void EgresPacketRouter::AddUDPHandler(huint16_t localport, EgresPacketHandlerFunc func)
    {
        if (m_IPProtoHandler.find(udp_proto) == m_IPProtoHandler.end())
        {
            m_IPProtoHandler.emplace(udp_proto, std::make_unique<EgresUDPPacketHandler>(m_BaseHandler));
        }
        m_IPProtoHandler[udp_proto]->AddSubHandler(ToNet(localport), std::move(func));
    }

    void EgresPacketRouter::AddIProtoHandler(uint8_t proto, EgresPacketHandlerFunc func)
    {
        m_IPProtoHandler[proto] = std::make_unique<EgresGenericLayer4Handler>(std::move(func));
    }

    void EgresPacketRouter::RemoveUDPHandler(huint16_t localport)
    {
        if (auto itr = m_IPProtoHandler.find(udp_proto); itr != m_IPProtoHandler.end())
        {
            itr->second->RemoveSubHandler(ToNet(localport));
        }
    }

}  // namespace llarp::vpn
