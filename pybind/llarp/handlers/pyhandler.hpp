#pragma once
#include <llarp.hpp>
#include <llarp/router/router.hpp>
#include <llarp/service/context.hpp>
#include <llarp/service/endpoint.hpp>

#include <common.hpp>

namespace llarp
{
    namespace handlers
    {
        using Context_ptr = std::shared_ptr<llarp::Context>;

        struct PythonEndpoint final : public llarp::service::Endpoint,
                                      public std::enable_shared_from_this<PythonEndpoint>
        {
            PythonEndpoint(std::string name, Context_ptr routerContext)
                : llarp::service::Endpoint(routerContext->router.get(), &routerContext->router->hiddenServiceContext()),
                  OurName(std::move(name))
            {}
            const std::string OurName;

            bool HandleInboundPacket(
                const service::ConvoTag tag,
                const llarp_buffer_t& pktbuf,
                service::ProtocolType proto,
                uint64_t) override
            {
                if (handlePacket)
                {
                    service::Address addr{};
                    if (auto maybe = GetEndpointWithConvoTag(tag))
                    {
                        if (auto ptr = std::get_if<service::Address>(&*maybe))
                            addr = *ptr;
                        else
                            return false;
                    }
                    else
                        return false;
                    std::vector<byte_t> pkt;
                    pkt.resize(pktbuf.sz);
                    std::copy_n(pktbuf.base, pktbuf.sz, pkt.data());
                    handlePacket(addr, std::move(pkt), proto);
                }
                return true;
            }

            std::shared_ptr<path::PathSet> GetSelf() override { return shared_from_this(); }

            std::weak_ptr<path::PathSet> GetWeak() override { return weak_from_this(); }

            bool SupportsV6() const override { return false; }

            llarp::huint128_t ObtainIPForAddr(std::variant<service::Address, RouterID>) override { return {0}; }

            std::optional<std::variant<service::Address, RouterID>> ObtainAddrForIP(huint128_t) const override
            {
                return std::nullopt;
            }

            std::string GetIfName() const override { return ""; }

            using PacketHandler_t = std::function<void(service::Address, std::vector<byte_t>, service::ProtocolType)>;

            PacketHandler_t handlePacket;

            void SendPacket(service::Address remote, std::vector<byte_t> pkt, service::ProtocolType proto)
            {
                m_router->loop()->call([remote, pkt, proto, self = shared_from_this()]() {
                    self->SendToOrQueue(remote, llarp_buffer_t(pkt), proto);
                });
            }

            void SendPacketToRemote(const llarp_buffer_t&, service::ProtocolType) override{};

            std::string GetOurAddress() const { return m_Identity.pub.Addr().ToString(); }
        };

        using PythonEndpoint_ptr = std::shared_ptr<PythonEndpoint>;
    }  // namespace handlers
}  // namespace llarp
