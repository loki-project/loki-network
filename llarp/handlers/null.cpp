#include "null.hpp"

namespace llarp::handlers
{
    static auto logcat = log::Cat("Null");

    NullEndpoint::NullEndpoint(Router& r)
        : BaseHandler{r}, _packet_router{new vpn::EgresPacketRouter{[](AddressVariant_t from, IPPacket pkt) {
              var::visit(
                  [&pkt](AddressVariant_t&& from) {
                      log::error(logcat, "Unhandled traffic from {} (pkt size:{}B)", from, pkt.size());
                  },
                  from);
          }}}
    {
        // r->loop()->add_ticker([this] { Pump(Now()); });
    }

    bool NullEndpoint::handle_inbound_packet(
        const service::SessionTag tag, const llarp_buffer_t& buf, service::ProtocolType t, uint64_t)
    {
        log::trace(logcat, "Inbound packet on session:{}", tag);

        if (t == service::ProtocolType::Control)
        {
            return true;
        }
        if (t == service::ProtocolType::TrafficV4 or t == service::ProtocolType::TrafficV6)
        {
            (void)buf;
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

            log::warning(logcat, "Failed to route packet convotag: {}", tag);
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
}  //  namespace llarp::handlers
