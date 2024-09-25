#include "route_poker.hpp"

#include "router.hpp"

#include <llarp/link/link_manager.hpp>

namespace llarp
{
    static auto logcat = log::Cat("route_poker");

    void RoutePoker::add_route(oxen::quic::Address ip)
    {
        if (not is_up)
            return;

        bool has_existing = poked_routes.count(ip);

        // set up route and apply as needed
        auto& gw = poked_routes[ip];

        if (current_gateway)
        {
            // remove existing mapping as needed
            if (has_existing)
                disable_route(ip, gw);
            // update and add new mapping
            gw = *current_gateway;

            log::info(logcat, "Added route to {} via {}", ip, gw);

            enable_route(ip, gw);
        }
        else
            gw = oxen::quic::Address{};
    }

    void RoutePoker::disable_route(oxen::quic::Address ip, oxen::quic::Address gateway)
    {
        if (ip.is_set() and gateway.is_set() and is_enabled())
        {
            vpn::AbstractRouteManager& route = router.vpn_platform()->RouteManager();
            route.delete_route(ip, gateway);
        }
    }

    void RoutePoker::enable_route(oxen::quic::Address ip, oxen::quic::Address gateway)
    {
        if (ip.is_set() and gateway.is_set() and is_enabled())
        {
            vpn::AbstractRouteManager& route = router.vpn_platform()->RouteManager();
            route.add_route(ip, gateway);
        }
    }

    void RoutePoker::delete_route(oxen::quic::Address ip)
    {
        if (const auto itr = poked_routes.find(ip); itr != poked_routes.end())
        {
            log::info(logcat, "Deleting route to {} via {}", itr->first, itr->second);
            disable_route(itr->first, itr->second);
            poked_routes.erase(itr);
        }
    }

    void RoutePoker::start()
    {
        if (not is_enabled())
            return;

        // router.loop()->call_every(100ms, weak_from_this(), [self = weak_from_this()]() {
        //     if (auto ptr = self.lock())
        //         ptr->update();
        // });
    }

    void RoutePoker::delete_all_routes()
    {
        // DelRoute will check enabled, so no need here
        for (const auto& item : poked_routes)
            delete_route(item.first);
    }

    void RoutePoker::disable_all_routes()
    {
        for (const auto& [ip, gateway] : poked_routes)
        {
            disable_route(ip, gateway);
        }
    }

    void RoutePoker::refresh_all_routes()
    {
        for (const auto& item : poked_routes)
            add_route(item.first);
    }

    RoutePoker::~RoutePoker()
    {
        if (not router.vpn_platform())
            return;

        auto& route = router.vpn_platform()->RouteManager();
        for (const auto& [ip, gateway] : poked_routes)
        {
            if (gateway.is_set() and ip.is_set())
                route.delete_route(ip, gateway);
        }
        route.delete_blackhole();
    }

    bool RoutePoker::is_enabled() const
    {
        if (router.is_service_node())
            return false;
        if (const auto& conf = router.config())
            return conf->network.enable_route_poker;

        throw std::runtime_error{"Attempting to use RoutePoker with router with no config set"};
    }

    void RoutePoker::update()
    {
        // // ensure we have an endpoint
        // auto ep = router.hidden_service_context().GetDefault();
        // if (ep == nullptr)
        //   return;
        // // ensure we have a vpn platform
        // auto* platform = router.vpn_platform();
        // if (platform == nullptr)
        //   return;
        // // ensure we have a vpn interface
        // auto* vpn = ep->GetVPNInterface();
        // if (vpn == nullptr)
        //   return;

        // auto& route = platform->RouteManager();

        // // get current gateways, assume sorted by lowest metric first
        // auto gateways = route.get_non_interface_gateways(*vpn);
        // std::optional<oxen::quic::Address> next_gw;

        // for (auto& g : gateways)
        // {
        //   if (g.is_ipv4())
        //   {
        //     next_gw = g;
        //     break;
        //   }
        // }

        // // update current gateway and apply state changes as needed
        // if (!(current_gateway == next_gw))
        // {
        //   if (next_gw and current_gateway)
        //   {
        //     log::info(logcat, "default gateway changed from {} to {}", *current_gateway,
        //     *next_gw); current_gateway = next_gw; refresh_all_routes();
        //   }
        //   else if (current_gateway)
        //   {
        //     log::warning(logcat, "default gateway {} has gone away", *current_gateway);
        //     current_gateway = next_gw;
        //   }
        //   else  // next_gw and not m_CurrentGateway
        //   {
        //     log::info(logcat, "default gateway found at {}", *next_gw);
        //     current_gateway = next_gw;
        //   }
        // }
        // else if (router.HasClientExit())
        //   put_up();
    }

    void RoutePoker::put_up()
    {
        bool was_up = is_up;
        is_up = true;
        if (not was_up)
        {
            if (not is_enabled())
            {
                log::warning(logcat, "RoutePoker coming up, but route poking is disabled by config");
            }
            else if (not current_gateway)
            {
                log::warning(logcat, "RokerPoker came up, but we don't know of a gateway!");
            }
            else
            {
                log::info(logcat, "RoutePoker coming up; poking routes");

                vpn::AbstractRouteManager& route = router.vpn_platform()->RouteManager();

                // black hole all routes if enabled
                if (router.config()->network.blackhole_routes)
                    route.add_blackhole();

                // explicit route pokes for first hops
                router.for_each_connection([this](link::Connection conn) { add_route(conn.conn->remote()); });

                add_route(router.link_manager()->local());
                // add default route
                // const auto ep = router.hidden_service_context().GetDefault();
                // if (auto* vpn = ep->GetVPNInterface())
                //   route.add_default_route_via_interface(*vpn);
                log::info(logcat, "route poker up");
            }
        }
        // if (not was_up)
        //   set_dns_mode(true);
    }

    void RoutePoker::put_down()
    {
        // unpoke routes for first hops
        router.for_each_connection([this](link::Connection conn) { delete_route(conn.conn->remote()); });
        if (is_enabled() and is_up)
        {
            // vpn::AbstractRouteManager& route = router.vpn_platform()->RouteManager();
            // const auto ep = router.hidden_service_context().GetDefault();
            // if (auto* vpn = ep->GetVPNInterface())
            //   route.delete_default_route_via_interface(*vpn);

            // delete route blackhole
            // route.delete_blackhole();
            // log::info(logcat, "route poker down");
        }
        // if (is_up)
        //   set_dns_mode(false);
        // is_up = false;
    }

}  // namespace llarp
