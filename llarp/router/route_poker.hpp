#pragma once

#include <oxen/quic.hpp>

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace llarp
{
    struct Router;

    struct RoutePoker : public std::enable_shared_from_this<RoutePoker>
    {
        RoutePoker(Router& r);

        void add_route(oxen::quic::Address ip);

        void delete_route(oxen::quic::Address ip);

        void start();

        ~RoutePoker();

        /// explicitly put routes up
        void put_up();

        /// explicitly put routes down
        void put_down();

        /// set dns resolver
        /// pass in if we are using exit node mode right now  as a bool void set_dns_mode(bool
        /// using_exit_mode) const;

        bool is_enabled() const { return _is_enabled; }

      private:
        void update();

        void delete_all_routes();

        void disable_all_routes();

        void refresh_all_routes();

        void enable_route(oxen::quic::Address ip, oxen::quic::Address gateway);

        void disable_route(oxen::quic::Address ip, oxen::quic::Address gateway);

        std::unordered_map<oxen::quic::Address, oxen::quic::Address> poked_routes;
        std::optional<oxen::quic::Address> current_gateway;

        Router& _router;
        bool _is_up{false};
        bool _is_enabled{false};
    };
}  // namespace llarp
