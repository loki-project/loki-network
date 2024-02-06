#include "packet_router.hpp"

namespace llarp::vpn
{
    struct UDPPacketHandler : public Layer4Handler
    {
        PacketHandlerFunc_t m_BaseHandler;
        std::unordered_map<nuint16_t, PacketHandlerFunc_t> m_LocalPorts;

        explicit UDPPacketHandler(PacketHandlerFunc_t baseHandler) : m_BaseHandler{std::move(baseHandler)}
        {}

        void AddSubHandler(nuint16_t localport, PacketHandlerFunc_t handler) override
        {
            m_LocalPorts.emplace(localport, std::move(handler));
        }

        void HandleIPPacket(llarp::net::IP_packet_deprecated pkt) override
        {
            auto dstport = pkt.DstPort();
            if (not dstport)
            {
                m_BaseHandler(std::move(pkt));
                return;
            }

            if (auto itr = m_LocalPorts.find(*dstport); itr != m_LocalPorts.end())
                itr->second(std::move(pkt));
            else
                m_BaseHandler(std::move(pkt));
        }
    };

    struct GenericLayer4Handler : public Layer4Handler
    {
        PacketHandlerFunc_t m_BaseHandler;

        explicit GenericLayer4Handler(PacketHandlerFunc_t baseHandler) : m_BaseHandler{std::move(baseHandler)}
        {}

        void HandleIPPacket(llarp::net::IP_packet_deprecated pkt) override
        {
            m_BaseHandler(std::move(pkt));
        }
    };

    PacketRouter::PacketRouter(PacketHandlerFunc_t baseHandler) : m_BaseHandler{std::move(baseHandler)}
    {}

    void PacketRouter::HandleIPPacket(llarp::net::IP_packet_deprecated pkt)
    {
        const auto proto = pkt.Header()->protocol;
        if (const auto itr = m_IPProtoHandler.find(proto); itr != m_IPProtoHandler.end())
            itr->second->HandleIPPacket(std::move(pkt));
        else
            m_BaseHandler(std::move(pkt));
    }

    void PacketRouter::AddUDPHandler(huint16_t localport, PacketHandlerFunc_t func)
    {
        constexpr uint8_t udp_proto = 0x11;

        if (m_IPProtoHandler.find(udp_proto) == m_IPProtoHandler.end())
        {
            m_IPProtoHandler.emplace(udp_proto, std::make_unique<UDPPacketHandler>(m_BaseHandler));
        }
        m_IPProtoHandler[udp_proto]->AddSubHandler(ToNet(localport), func);
    }

    void PacketRouter::AddIProtoHandler(uint8_t proto, PacketHandlerFunc_t func)
    {
        m_IPProtoHandler[proto] = std::make_unique<GenericLayer4Handler>(std::move(func));
    }

}  // namespace llarp::vpn
