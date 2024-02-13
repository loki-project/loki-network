
#include "vpn_interface.hpp"

#include "context.hpp"

#include <llarp/router/router.hpp>

namespace llarp::apple
{
    VPNInterface::VPNInterface(
        Context& ctx, packet_write_callback packet_writer, on_readable_callback on_readable, Router* router)
        : vpn::NetworkInterface{{}},
          _pkt_writer{std::move(packet_writer)},
          _on_readable{std::move(on_readable)},
          _router{router}
    {
        ctx._loop->call_soon([this] { _on_readable(*this); });
    }

    bool VPNInterface::OfferReadPacket(const llarp_buffer_t& buf)
    {
        IPPacket pkt;
        if (!pkt.load(buf.copy()))
            return false;
        _read_que.tryPushBack(std::move(pkt));
        return true;
    }

    void VPNInterface::MaybeWakeUpperLayers() const
    {
        //
    }

    int VPNInterface::PollFD() const
    {
        return -1;
    }

    IPPacket VPNInterface::ReadNextPacket()
    {
        IPPacket pkt{};
        if (not _read_que.empty())
            pkt = _read_que.popFront();
        return pkt;
    }

    bool VPNInterface::WritePacket(IPPacket pkt)
    {
        // TODO: replace this with IPPacket::to_udp
        (void)pkt;
        // int af_family = pkt() ? AF_INET6 : AF_INET;
        // return _pkt_writer(af_family, pkt.data(), pkt.size());
        return true;
    }

}  // namespace llarp::apple
