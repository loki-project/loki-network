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

        virtual vpn::NetworkInterface* GetVPNInterface() = 0;

        virtual std::string GetIfName() const = 0;

        virtual bool SupportsV6() const = 0;

        virtual bool configure(const NetworkConfig& conf, const DnsConfig& dnsConf) = 0;

        virtual bool SetupNetworking() = 0;

        virtual void load_key_file(std::optional<fs::path> p, Router& r);

        virtual vpn::EgresPacketRouter* EgresPacketRouter()
        {
            return nullptr;
        };

        virtual huint128_t ObtainIPForAddr(std::variant<service::Address, RouterID>) = 0;

        /// get a key for ip address
        virtual std::optional<std::variant<service::Address, RouterID>> ObtainAddrForIP(huint128_t ip) const = 0;

        /// handle packet io from service node or hidden service to frontend
        virtual bool HandleInboundPacket(
            const service::SessionTag tag, const llarp_buffer_t& pkt, service::ProtocolType t, uint64_t seqno) = 0;
    };
}  // namespace llarp::handlers
