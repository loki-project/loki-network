#pragma once

#include "common.hpp"

#include <llarp/address/ip_range.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/endpoint_base.hpp>
#include <llarp/handlers/remote.hpp>
#include <llarp/session/session.hpp>

#include <unordered_map>

namespace llarp
{
    inline constexpr size_t NUM_ONS_LOOKUP_PATHS{4};

    inline constexpr size_t NUM_SESSION_PATHS{4};

    namespace handlers
    {
        /** This class holds methods common to session management to remote hidden services and
           nodes. Specifically, it is extended by service::Handler and exit::Handler, which
           respectively manage sessions to remote hidden services and exit nodes.
        */
        struct RemoteHandler : public EndpointBase, public path::PathHandler
        {
           protected:
            std::string _name;
            net::IPRangeMap<service::Address> _ip_map;

            DnsConfig _dns_config;
            NetworkConfig _net_config;

            IPRange _ip_range;
            IPRange _if_addr;
            IPRange _next_addr;

            std::string _if_name;

            bool _use_v6;

           public:
            RemoteHandler(std::string name, Router& r);
            ~RemoteHandler() override;

            void configure(const NetworkConfig& networkConfig, const DnsConfig& dnsConfig);

            std::string name() const override
            {
                return _name;
            }

            bool supports_ipv6() const
            {
                return _use_v6;
            }

            IPRange if_addr() const
            {
                return _if_addr;
            }

            // lookup ONS address for a ".loki" hidden service or exit node operated on a remote
            // client
            virtual void lookup_name(std::string name, std::function<void(std::string, bool)> func = nullptr);

            virtual void lookup_remote_srv(
                std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler);

            virtual bool initiate_session_to_remote(const RouterID& remote);

            void build_more(size_t n = 0) override;

            link::TunnelManager* GetQUICTunnel() override
            {
                return nullptr;
            }

            AddressVariant_t local_address() const override;

            const std::shared_ptr<EvLoop_deprecated>& loop() override;

            void srv_records_changed() override;

            void Tick(llarp_time_t now) override;

            void map_remote(
                std::string name,
                std::string token,
                std::vector<IPRange> ranges,
                std::function<void(bool, std::string)> result);

            void map_range(IPRange range, service::Address exit);

            void unmap_range(IPRange range);

            void unmap_range_by_remote(IPRange range, std::string exit);
        };
    }  // namespace handlers
}  // namespace llarp
