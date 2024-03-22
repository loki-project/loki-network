#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>
#include <llarp/address/ip_range.hpp>
#include <llarp/address/map.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/endpoint_base.hpp>
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

            address_map<oxen::quic::Address, ClientAddress> _client_address_map;
            address_map<IPRange, ClientAddress> _client_range_map;

            DnsConfig _dns_config;
            NetworkConfig _net_config;

            IPRange _local_range;
            oxen::quic::Address _local_addr;
            ip _local_ip;

            ip _next_ip;

            std::string _if_name;

            bool _use_v6;

            // Private method that {exit,service}::Handler can override
            virtual void _configure() = 0;

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

            oxen::quic::Address if_addr() const
            {
                return _local_addr;
            }

            // lookup ONS address to return "{pubkey}.loki" hidden service or exit node operated on a remote client
            virtual void lookup_name(
                std::string name, std::function<void(std::optional<ClientAddress>)> func = nullptr);

            virtual void lookup_remote_srv(
                std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler);

            virtual bool initiate_session_to_remote(const RouterID& remote);

            void build_more(size_t n = 0) override;

            link::TunnelManager* GetQUICTunnel() override
            {
                return nullptr;
            }

            oxen::quic::Address local_address() const override
            {
                return if_addr();
            }

            const std::shared_ptr<EventLoop>& loop() override;

            void srv_records_changed() override;

            void Tick(llarp_time_t now) override;

            /*  Address Mapping - Public Mutators  */
            void map_remote_to_local_addr(ClientAddress remote, oxen::quic::Address local);

            void unmap_local_addr_by_remote(ClientAddress remote);

            void unmap_remote_by_name(std::string name);

            /*  IPRange Mapping - Public Mutators  */
            void map_remote_to_local_range(ClientAddress remote, IPRange range);

            void unmap_local_range_by_remote(ClientAddress remote);

            void unmap_range_by_name(std::string name);
        };
    }  // namespace handlers
}  // namespace llarp
