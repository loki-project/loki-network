#pragma once

#include <llarp/auth/auth.hpp>
#include <llarp/dns/server.hpp>
#include <llarp/ev/loop.hpp>
#include <llarp/net/net.hpp>
#include <llarp/service/identity.hpp>
#include <llarp/service/name.hpp>
#include <llarp/session/session.hpp>
#include <llarp/vpn/egres_packet_router.hpp>

#include <oxenc/variant.h>

#include <optional>
#include <unordered_map>
#include <variant>

namespace llarp::handlers
{

    /** This class holds methods common to handlers::{Tun,Null}Endpoints in regards to their packet
        routing and other API capabilities.
    */
    struct BaseHandler
    {
      protected:
        Router& _router;

      public:
        BaseHandler(Router& r) : _router{r}
        {}

        virtual std::string name() const = 0;

        const Router& router() const
        {
            return _router;
        }

        Router& router()
        {
            return _router;
        }

        const std::shared_ptr<EventLoop>& loop() const;

        virtual ~BaseHandler() = default;

        service::Identity _identity;

        virtual vpn::NetworkInterface* get_vpn_interface() = 0;

        virtual std::string get_if_name() const = 0;

        virtual bool supports_ipv6() const = 0;

        virtual bool configure() = 0;

        virtual bool setup_networking() = 0;

        virtual void load_key_file(std::optional<fs::path> p);

        virtual vpn::EgresPacketRouter* egres_packet_router()
        {
            return nullptr;
        };

        /// handle packet io from service node or hidden service to frontend
        virtual bool handle_inbound_packet(
            const service::SessionTag tag, const llarp_buffer_t& pkt, service::ProtocolType t, uint64_t seqno) = 0;
    };
}  // namespace llarp::handlers
