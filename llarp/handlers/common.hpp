#pragma once

#include <llarp/auth/auth.hpp>
#include <llarp/dns/server.hpp>
#include <llarp/net/ip_range_map.hpp>
#include <llarp/net/net.hpp>
#include <llarp/service/address.hpp>
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

        virtual ~BaseHandler() = default;

        service::Identity _identity;

        virtual vpn::NetworkInterface* get_vpn_interface() = 0;

        virtual std::string get_if_name() const = 0;

        virtual bool supports_ipv6() const = 0;

        virtual bool configure(const NetworkConfig& conf, const DnsConfig& dnsConf) = 0;

        virtual bool setup_networking() = 0;

        virtual void load_key_file(std::optional<fs::path> p, Router& r);

        virtual vpn::EgresPacketRouter* egres_packet_router()
        {
            return nullptr;
        };

        virtual huint128_t get_ip_for_addr(std::variant<service::Address, RouterID>) = 0;

        /// get a key for ip address
        virtual std::optional<std::variant<service::Address, RouterID>> get_addr_for_ip(huint128_t ip) const = 0;

        /// handle packet io from service node or hidden service to frontend
        virtual bool handle_inbound_packet(
            const service::SessionTag tag, const llarp_buffer_t& pkt, service::ProtocolType t, uint64_t seqno) = 0;
    };
}  // namespace llarp::handlers
