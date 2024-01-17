#pragma once

#include "common.hpp"

#include <llarp/link/tunnel.hpp>
#include <llarp/router/router.hpp>
#include <llarp/service/endpoint.hpp>
#include <llarp/service/handler.hpp>
#include <llarp/vpn/egres_packet_router.hpp>

namespace llarp::handlers
{
    struct NullEndpoint final : public dns::Resolver_Base,
                                public BaseHandler,
                                public std::enable_shared_from_this<NullEndpoint>
    {
        NullEndpoint(Router& r)
            : BaseHandler{r}, _packet_router{new vpn::EgresPacketRouter{[](AddressVariant_t from, net::IPPacket pkt) {
                  var::visit(
                      [&pkt](AddressVariant_t&& from) {
                          log::error(logcat, "Unhandled traffic from {} (pkt size:{}B)", from, pkt.size());
                      },
                      from);
              }}}
        {
            // r->loop()->add_ticker([this] { Pump(Now()); });
        }

        vpn::NetworkInterface* GetVPNInterface() override
        {
            return nullptr;
        }

        int Rank() const override
        {
            return 0;
        }

        std::string name() const override
        {
            return "null"s;
        }

        std::string_view ResolverName() const override
        {
            return "lokinet";
        }

        bool MaybeHookDNS(
            std::shared_ptr<dns::PacketSource_Base> /* source */,
            const dns::Message& /* query */,
            const SockAddr& /* to */,
            const SockAddr& /* from */) override
        {
            return false;
        }

        bool SetupNetworking() override
        {
            return true;
        }

        // TODO: this
        bool configure(const NetworkConfig& conf, const DnsConfig& dnsConf) override
        {
            (void)conf;
            (void)dnsConf;
            return true;
        }

        bool HandleInboundPacket(
            const service::SessionTag tag, const llarp_buffer_t& buf, service::ProtocolType t, uint64_t) override
        {
            LogTrace("Inbound ", t, " packet (", buf.sz, "B) on convo ", tag);
            if (t == service::ProtocolType::Control)
            {
                return true;
            }
            if (t == service::ProtocolType::TrafficV4 or t == service::ProtocolType::TrafficV6)
            {
                // if (auto from = GetEndpointWithConvoTag(tag))
                // {
                //   net::IPPacket pkt{};
                //   if (not pkt.Load(buf))
                //   {
                //     LogWarn("invalid ip packet from remote T=", tag);
                //     return false;
                //   }
                //   _packet_router->HandleIPPacketFrom(std::move(*from), std::move(pkt));
                //   return true;
                // }

                LogWarn("did not handle packet, no endpoint with convotag T=", tag);
                return false;
            }
            if (t != service::ProtocolType::QUIC)
                return false;

            // auto* quic = GetQUICTunnel();
            // if (!quic)
            // {
            //   LogWarn("incoming quic packet but this endpoint is not quic capable; dropping");
            //   return false;
            // }
            // if (buf.sz < 4)
            // {
            //   LogWarn("invalid incoming quic packet, dropping");
            //   return false;
            // }
            // TODO:
            // quic->receive_packet(tag, buf);
            return true;
        }

        std::string GetIfName() const override
        {
            return "";
        }

        bool SupportsV6() const override
        {
            return false;
        }

        huint128_t ObtainIPForAddr(std::variant<service::Address, RouterID>) override
        {
            return {0};
        }

        std::optional<std::variant<service::Address, RouterID>> ObtainAddrForIP(huint128_t) const override
        {
            return std::nullopt;
        }

        vpn::EgresPacketRouter* EgresPacketRouter() override
        {
            return _packet_router.get();
        }

       private:
        std::unique_ptr<vpn::EgresPacketRouter> _packet_router;
    };
}  // namespace llarp::handlers
