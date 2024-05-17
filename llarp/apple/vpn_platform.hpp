#pragma once

#include "route_manager.hpp"
#include "vpn_interface.hpp"

#include <llarp/vpn/platform.hpp>

namespace llarp::apple
{
    class VPNPlatform final : public vpn::Platform
    {
      public:
        explicit VPNPlatform(
            Context& ctx,
            VPNInterface::packet_write_callback packet_writer,
            VPNInterface::on_readable_callback on_readable,
            llarp_route_callbacks route_callbacks,
            void* callback_context);

        std::shared_ptr<vpn::NetworkInterface> ObtainInterface(vpn::InterfaceInfo, Router*) override;

        vpn::AbstractRouteManager& RouteManager() override { return _route_manager; }

      private:
        Context& _context;
        apple::RouteManager _route_manager;
        VPNInterface::packet_write_callback _packet_writer;
        VPNInterface::on_readable_callback _read_cb;
    };

}  // namespace llarp::apple
