#pragma once

#include <llarp/address/ip_range.hpp>
#include <llarp/address/map.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/config/config.hpp>
#include <llarp/endpoint_base.hpp>
#include <llarp/session/session.hpp>

namespace llarp
{
    inline constexpr size_t NUM_SESSION_PATHS{4};
    inline constexpr size_t NUM_ONS_LOOKUP_PATHS{4};

    namespace handlers
    {
        /** This class holds methods common to session management to remote hidden services and
            nodes. Specifically, it is extended by service::Handler and exit::Handler, which
            respectively manage sessions to remote hidden services and exit nodes.
        */
        struct RemoteHandler final : public EndpointBase,
                                     public path::PathHandler,
                                     public std::enable_shared_from_this<RemoteHandler>
        {
          private:
            std::string _name;

            address_map<oxen::quic::Address, NetworkAddress> _address_map;

            address_map<IPRange, NetworkAddress> _range_map;

            DnsConfig _dns_config;
            NetworkConfig _net_config;

            IPRange _local_range;
            oxen::quic::Address _local_addr;

            ip _local_ip;
            ip _next_ip;

            std::string _if_name;

            bool _use_v6;

          public:
            RemoteHandler(std::string name, Router& r);
            ~RemoteHandler() override;

            std::shared_ptr<PathHandler> get_self() override
            {
                return shared_from_this();
            }

            std::weak_ptr<PathHandler> get_weak() override
            {
                return weak_from_this();
            }

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
            void resolve_ons(std::string name, std::function<void(std::optional<NetworkAddress>)> func = nullptr);

            void lookup_remote_srv(
                std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler);

            void lookup_intro(
                RouterID remote,
                bool is_relayed,
                uint64_t order,
                std::function<void(std::optional<service::IntroSet>)> func);

            template <NetworkAddrType net_addr_t>
            bool initiate_remote_service_session(net_addr_t& remote)
            {
                RouterID rid{remote.pubkey().data()};

                if constexpr (std::is_same_v<decltype(remote), NetworkAddress>)
                {
                    return initiate_session(rid, true, false);
                }
                if constexpr (std::is_same_v<decltype(remote), RelayAddress>)
                {
                    return initiate_session(rid, false, true);
                }

                return false;
            }

            bool initiate_remote_exit_session(NetworkAddress& remote)
            {
                RouterID rid{remote.pubkey().data()};
                return initiate_session(rid, true, false);
            }

            // RemoteHandler does not build paths to the remote addresses it maintains sessions to; each OutboundSession
            // maintains its own paths, while RemoteHandler maintains paths for introset lookups
            void build_more(size_t n = 0) override;

            oxen::quic::Address local_address() const override
            {
                return if_addr();
            }

            const std::shared_ptr<EventLoop>& loop() override;

            void srv_records_changed() override;

            void Tick(std::chrono::milliseconds now) override;

            /*  Address Mapping - Public Mutators  */
            void map_remote_to_local_addr(NetworkAddress remote, oxen::quic::Address local);

            void unmap_local_addr_by_remote(const NetworkAddress& remote);

            void unmap_remote_by_name(const std::string& name);

            /*  IPRange Mapping - Public Mutators  */
            void map_remote_to_local_range(NetworkAddress remote, IPRange range);

            void unmap_local_range_by_remote(const NetworkAddress& remote);

            void unmap_range_by_name(const std::string& name);

          private:
            bool initiate_session(RouterID remote, bool is_exit = false, bool is_snode = false);

            void make_session_path(RouterID remote, bool is_exit, bool is_snode);

            void make_session(RouterID remote, std::shared_ptr<path::Path> path, bool is_exit, bool is_snode);
        };
    }  // namespace handlers
}  // namespace llarp
