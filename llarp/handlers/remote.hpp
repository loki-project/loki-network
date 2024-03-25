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
          protected:  // TODO: make this private if/when deprecating derived types
            std::string _name;

            // TODO: make this hold {Client,Relay}Address
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
            void resolve_ons(std::string name, std::function<void(std::optional<ClientAddress>)> func = nullptr);

            void lookup_remote_srv(
                std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler);

            template <NetworkAddrType net_addr_t>
            bool initiate_remote_service_session(net_addr_t& remote)
            {
                if constexpr (std::is_same_v<decltype(remote), ClientAddress>)
                {
                    if (auto maybe_pk = remote.pubkey())
                    {
                        RouterID rid{maybe_pk.data()};
                        return initiate_session(rid);
                    }
                }
                if constexpr (std::is_same_v<decltype(remote), RelayAddress>)
                {
                    RouterID rid{remote.pubkey().data()};
                    return initiate_session(rid, false, true);
                }

                return false;
            }

            bool initiate_remote_exit_session(ClientAddress& remote)
            {
                if (auto maybe_pk = remote.pubkey())
                {
                    RouterID rid{maybe_pk->data()};
                    return initiate_session(rid, true, false);
                }
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
            void map_remote_to_local_addr(ClientAddress remote, oxen::quic::Address local);

            void unmap_local_addr_by_remote(const ClientAddress& remote);

            void unmap_remote_by_name(const std::string& name);

            /*  IPRange Mapping - Public Mutators  */
            void map_remote_to_local_range(ClientAddress remote, IPRange range);

            void unmap_local_range_by_remote(const ClientAddress& remote);

            void unmap_range_by_name(const std::string& name);

          private:
            bool initiate_session(RouterID remote, bool is_exit = false, bool is_snode = false);
        };
    }  // namespace handlers
}  // namespace llarp
