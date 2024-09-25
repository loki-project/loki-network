#pragma once

#include "context_wrapper.h"

#include <llarp/router/router.hpp>
#include <llarp/vpn/platform.hpp>

namespace llarp::apple
{
    class RouteManager final : public llarp::vpn::AbstractRouteManager
    {
      public:
        RouteManager(llarp::Context& ctx, llarp_route_callbacks rcs, void* callback_context)
            : context{ctx}, callback_context{callback_context}, route_callbacks{std::move(rcs)}
        {}

        /// These are called for poking route holes, but we don't have to do that at all on macos
        /// because the appex isn't subject to its own rules.
        void add_route(oxen::quic::Address /*ip*/, oxen::quic::Address /*gateway*/) override {}

        void delete_route(oxen::quic::Address /*ip*/, oxen::quic::Address /*gateway*/) override {}

        void add_default_route_via_interface(vpn::NetworkInterface& vpn) override;

        void delete_default_route_via_interface(vpn::NetworkInterface& vpn) override;

        void add_route_via_interface(vpn::NetworkInterface& vpn, IPRange range) override;

        void delete_route_via_interface(vpn::NetworkInterface& vpn, IPRange range) override;

        std::vector<oxen::quic::Address> get_non_interface_gateways(vpn::NetworkInterface& /*vpn*/) override
        {
            // We can't get this on mac from our sandbox, but we don't actually need it because we
            // ignore the gateway for AddRoute/DelRoute anyway, so just return a zero IP.
            return std::vector<oxen::quic::Address>{};
        }

      private:
        llarp::Context& context;
        bool trampoline_active = false;
        void check_trampoline(bool enable);

        void* callback_context = nullptr;
        llarp_route_callbacks route_callbacks;
    };

}  // namespace llarp::apple
