#include "vpn_platform.hpp"

#include "context.hpp"

namespace llarp::apple
{
    VPNPlatform::VPNPlatform(
        Context& ctx,
        VPNInterface::packet_write_callback packet_writer,
        VPNInterface::on_readable_callback on_readable,
        llarp_route_callbacks route_callbacks,
        void* callback_context)
        : _context{ctx},
          _route_manager{ctx, std::move(route_callbacks), callback_context},
          _packet_writer{std::move(packet_writer)},
          _read_cb{std::move(on_readable)}
    {}

    std::shared_ptr<vpn::NetworkInterface> VPNPlatform::obtain_interface(vpn::InterfaceInfo, Router* router)
    {
        return std::make_shared<VPNInterface>(_context, _packet_writer, _read_cb, router);
    }
}  // namespace llarp::apple
