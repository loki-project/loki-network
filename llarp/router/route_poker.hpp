#pragma once

#include <llarp/net/net_int.hpp>

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
        RoutePoker(Router& r) : router{r}
        {}

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

      private:
        void update();

        bool is_enabled() const;

        void delete_all_routes();

        void disable_all_routes();

        void refresh_all_routes();

        void enable_route(oxen::quic::Address ip, oxen::quic::Address gateway);

        void disable_route(oxen::quic::Address ip, oxen::quic::Address gateway);

        std::unordered_map<oxen::quic::Address, oxen::quic::Address> poked_routes;

        std::optional<oxen::quic::Address> current_gateway;

        Router& router;
        bool is_up{false};
    };
}  // namespace llarp
