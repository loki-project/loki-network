#pragma once

#include "tun.hpp"

#include <llarp/dns/server.hpp>
#include <llarp/exit/endpoint.hpp>

#include <unordered_map>

namespace llarp
{
    struct Router;
}

namespace llarp::handlers
{
    struct ExitEndpoint : public dns::Resolver_Base, public EndpointBase
    {
        int Rank() const override
        {
            return 0;
        };

        std::string_view ResolverName() const override
        {
            return "snode";
        }

        bool MaybeHookDNS(
            std::shared_ptr<dns::PacketSource_Base> source,
            const dns::Message& query,
            const SockAddr& to,
            const SockAddr& from) override;

        ExitEndpoint(std::string name, Router* r);
        ~ExitEndpoint() override;

        std::optional<AddressVariant_t> GetEndpointWithConvoTag(service::ConvoTag tag) const override;

        std::optional<service::ConvoTag> GetBestConvoTagFor(AddressVariant_t addr) const override;

        bool EnsurePathTo(
            AddressVariant_t addr,
            std::function<void(std::optional<service::ConvoTag>)> hook,
            llarp_time_t timeout) override;

        void lookup_name(std::string name, std::function<void(std::string, bool)> func) override;

        const EventLoop_ptr& Loop() override;

        std::unordered_set<EndpointBase::AddressVariant_t> AllRemoteEndpoints() const override;

        void SRVRecordsChanged() override;

        void MarkAddressOutbound(service::Address) override{};

        bool send_to(service::ConvoTag tag, std::string payload) override;

        void Tick(llarp_time_t now);

        void Configure(const NetworkConfig& networkConfig, const DnsConfig& dnsConfig);

        std::string Name() const;

        bool VisitEndpointsFor(const PubKey& pk, std::function<bool(exit::Endpoint* const)> visit) const;

        util::StatusObject ExtractStatus() const;

        bool SupportsV6() const;

        bool ShouldHookDNSMessage(const dns::Message& msg) const;

        bool HandleHookedDNSMessage(dns::Message msg, std::function<void(dns::Message)>);

        void LookupServiceAsync(
            std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler) override;

        bool AllocateNewExit(const PubKey pk, const PathID_t& path, bool permitInternet);

        exit::Endpoint* FindEndpointByPath(const PathID_t& path);

        exit::Endpoint* FindEndpointByIP(huint32_t ip);

        bool UpdateEndpointPath(const PubKey& remote, const PathID_t& next);

        /// handle ip packet from outside
        void OnInetPacket(net::IPPacket buf);

        Router* GetRouter();

        llarp_time_t Now() const;

        template <typename Stats>
        void CalculateTrafficStats(Stats& stats)
        {
            for (auto& [pubkey, endpoint] : active_exits)
            {
                stats[pubkey].first += endpoint->TxRate();
                stats[pubkey].second += endpoint->RxRate();
            }
        }

        /// DO NOT CALL ME
        void DelEndpointInfo(const PathID_t& path);

        /// DO NOT CALL ME
        void RemoveExit(const exit::Endpoint* ep);

        bool QueueOutboundTraffic(net::IPPacket pkt);

        AddressVariant_t LocalAddress() const override;

        std::optional<SendStat> GetStatFor(AddressVariant_t remote) const override;

        /// sets up networking and starts traffic
        bool Start();

        bool Stop();

        bool ShouldRemove() const;

        bool HasLocalMappedAddrFor(const PubKey& pk) const;

        huint128_t GetIfAddr() const;

        void Flush();

        link::TunnelManager* GetQUICTunnel() override;

        huint128_t GetIPForIdent(const PubKey pk);
        /// async obtain snode session and call callback when it's ready to send
        void ObtainSNodeSession(const RouterID& rid, exit::SessionReadyFunc obtain_cb);

      private:
        huint128_t AllocateNewAddress();

        /// obtain ip for service node session, creates a new session if one does
        /// not existing already
        huint128_t ObtainServiceNodeIP(const RouterID& router);

        bool QueueSNodePacket(const llarp_buffer_t& buf, huint128_t from);

        void MarkIPActive(huint128_t ip);

        void KickIdentOffExit(const PubKey& pk);

        Router* router;
        std::shared_ptr<dns::Server> resolver;
        bool should_init_tun;
        std::string name;
        bool permit_exit;
        std::unordered_map<PathID_t, PubKey> paths;

        std::unordered_map<PubKey, exit::Endpoint*> chosen_exits;

        std::unordered_multimap<PubKey, std::unique_ptr<exit::Endpoint>> active_exits;

        std::unordered_map<PubKey, huint128_t> key_to_IP;

        using SNodes_t = std::set<PubKey>;
        /// set of pubkeys we treat as snodes
        SNodes_t snode_keys;

        using SNodeSessions_t = std::unordered_map<RouterID, std::shared_ptr<exit::SNodeSession>>;
        /// snode sessions we are talking to directly
        SNodeSessions_t snode_sessions;

        std::unordered_map<huint128_t, PubKey> ip_to_key;

        huint128_t if_addr;
        huint128_t highest_addr;

        huint128_t next_addr;
        IPRange ip_range;
        std::string if_name;

        std::unordered_map<huint128_t, llarp_time_t> ip_activity;

        std::shared_ptr<vpn::NetworkInterface> if_net;

        SockAddr resolver_addr;
        std::vector<SockAddr> upstream_resolvers;

        // std::shared_ptr<link::TunnelManager> tunnel_manager;

        using PacketQueue_t =
            std::priority_queue<net::IPPacket, std::vector<net::IPPacket>, net::IPPacket::CompareOrder>;

        /// internet to llarp packet queue
        PacketQueue_t inet_to_network;
        bool use_ipv6;
        DnsConfig dns_conf;
    };
}  // namespace llarp::handlers
