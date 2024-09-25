#include "route_manager.hpp"

#include <llarp.hpp>
#include <llarp/handlers/tun.hpp>

#include <memory>

namespace llarp::apple
{
    static auto logcat = log::Cat("apple.route_manager");

    void RouteManager::check_trampoline(bool enable)
    {
        if (trampoline_active == enable)
            return;
        auto router = context.router;
        if (!router)
        {
            log::error(logcat, "Cannot reconfigure to use DNS trampoline: no router");
            return;
        }

        std::shared_ptr<llarp::handlers::TunEndpoint> tun;
        router->hidden_service_context().ForEachService([&tun](const auto& /*name*/, const auto ep) {
            tun = std::dynamic_pointer_cast<llarp::handlers::TunEndpoint>(ep);
            return !tun;
        });

        if (!tun)
        {
            log::error(logcat, "Cannot reconfigure to use DNS trampoline: no tun endpoint found (!?)");
            return;
        }

        if (enable)
            tun->ReconfigureDNS({SockAddr{127, 0, 0, 1, {dns_trampoline_port}}});
        else
            tun->ReconfigureDNS(router->config()->dns.upstream_dns);

        trampoline_active = enable;
    }

    void RouteManager::add_default_route_via_interface(vpn::NetworkInterface&)
    {
        check_trampoline(true);
        if (callback_context and route_callbacks.add_default_route)
            route_callbacks.add_default_route(callback_context);
    }

    void RouteManager::delete_default_route_via_interface(vpn::NetworkInterface&)
    {
        check_trampoline(false);
        if (callback_context and route_callbacks.del_default_route)
            route_callbacks.del_default_route(callback_context);
    }

    void RouteManager::add_route_via_interface(vpn::NetworkInterface&, IPRange range)
    {
        check_trampoline(true);
        if (callback_context)
        {
            if (range.IsV4())
            {
                if (route_callbacks.add_ipv4_route)
                    route_callbacks.add_ipv4_route(
                        range.BaseAddressString().c_str(),
                        net::TruncateV6(range.netmask_bits).to_string().c_str(),
                        callback_context);
            }
            else
            {
                if (route_callbacks.add_ipv6_route)
                    route_callbacks.add_ipv6_route(
                        range.BaseAddressString().c_str(), range.HostmaskBits(), callback_context);
            }
        }
    }

    void RouteManager::delete_route_via_interface(vpn::NetworkInterface&, IPRange range)
    {
        check_trampoline(false);
        if (callback_context)
        {
            if (range.IsV4())
            {
                if (route_callbacks.del_ipv4_route)
                    route_callbacks.del_ipv4_route(
                        range.BaseAddressString().c_str(),
                        net::TruncateV6(range.netmask_bits).to_string().c_str(),
                        callback_context);
            }
            else
            {
                if (route_callbacks.del_ipv6_route)
                    route_callbacks.del_ipv6_route(
                        range.BaseAddressString().c_str(), range.HostmaskBits(), callback_context);
            }
        }
    }

}  // namespace llarp::apple
