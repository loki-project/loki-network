#pragma once

#include <llarp/address/map.hpp>
#include <llarp/dns/server.hpp>
#include <llarp/net/ip_packet.hpp>
#include <llarp/util/thread/threading.hpp>
#include <llarp/vpn/packet_router.hpp>
#include <llarp/vpn/platform.hpp>

#include <future>
#include <type_traits>
#include <variant>

namespace llarp::handlers
{
    inline constexpr auto TUN = "tun"sv;
    inline constexpr auto LOKI_RESOLVER = "lokinet"sv;

    struct TunEndpoint : public dns::Resolver_Base, public std::enable_shared_from_this<TunEndpoint>
    {
        TunEndpoint(Router& r);
        ~TunEndpoint() override;

      private:
        Router& _router;

        /// dns subsystem for this endpoint
        std::shared_ptr<dns::Server> _dns;

        /// our local ip range (config-mapped as `if-addr`), address, and ip
        IPRange _local_range;
        oxen::quic::Address _local_addr;
        ip_v _local_base_ip;

        IPRangeIterator _local_range_iterator;

        /// Our local Network Address holding our network pubkey
        NetworkAddress _local_netaddr;

        /// our network interface's ipv6 address
        oxen::quic::Address _local_ipv6;

        /// list of strict connect addresses for hooks
        // std::vector<IpAddress> _strict_connect_addrs;
        /// use v6?
        bool ipv6_enabled{};

        std::string _if_name;

        std::optional<IPRange> _base_ipv6_range = std::nullopt;

        std::shared_ptr<vpn::NetworkInterface> _net_if;
        std::shared_ptr<FDPoller> _poller;

        std::shared_ptr<vpn::PacketRouter> _packet_router;

        std::optional<net::ExitPolicy> _exit_policy = std::nullopt;

        /// a file to load / store the ephemeral address map to
        std::optional<fs::path> _persisting_addr_file = std::nullopt;
        bool persist_addrs{false};

        /// how long to wait for path alignment
        std::chrono::milliseconds _path_alignment_timeout{30s};

        /// for raw packet dns
        std::shared_ptr<vpn::PacketIO> _raw_DNS;

      public:
        vpn::NetworkInterface* get_vpn_interface() { return _net_if.get(); }

        std::string_view name() const { return TUN; }

        int rank() const override { return 0; }

        std::string_view resolver_name() const override { return LOKI_RESOLVER; }

        bool maybe_hook_dns(
            std::shared_ptr<dns::PacketSource_Base> source,
            const dns::Message& query,
            const oxen::quic::Address& to,
            const oxen::quic::Address& from) override;

        // Reconfigures DNS servers and restarts libunbound with the new servers.
        void reconfigure_dns(std::vector<oxen::quic::Address> servers);

        void configure();

        std::string get_if_name() const;

        nlohmann::json ExtractStatus() const;

        bool supports_ipv6() const;

        bool should_hook_dns_message(const dns::Message& msg) const;

        bool handle_hooked_dns_message(dns::Message query, std::function<void(dns::Message)> sendreply);

        void tick_tun(std::chrono::milliseconds now);

        bool stop();

        bool is_service_node() const;

        bool is_exit_node() const;

        void setup_dns();

        // INPROGRESS: new API
        // Handles an outbound packet going OUT to the network
        void handle_outbound_packet(IPPacket pkt);

        void rewrite_and_send_packet(IPPacket&& pkt, ip_v src, ip_v dest);

        // Handles an inbound packet coming IN from the network
        bool handle_inbound_packet(IPPacket pkt, NetworkAddress remote, bool is_exit_session, bool is_outbound_session);

        // Upon session creation, SessionHandler will instruct TunEndpoint to requisition a private IP through which to
        // route session traffic
        std::optional<ip_v> map_session_to_local_ip(const NetworkAddress& remote);

        void unmap_session_to_local_ip(const NetworkAddress& remote);

        oxen::quic::Address get_if_addr() const;

        bool has_if_addr() const { return true; }

        std::optional<net::ExitPolicy> get_traffic_policy() const { return _exit_policy; }

        std::chrono::milliseconds get_path_alignment_timeout() const { return _path_alignment_timeout; }

        /// ip packet against any exit policies we have
        /// returns false if this traffic is disallowed by any of those policies
        /// returns true otherwise
        bool is_allowing_traffic(const IPPacket& pkt) const;

        bool has_mapping_to_remote(const NetworkAddress& addr) const;

        std::optional<ip_v> get_mapped_ip(const NetworkAddress& addr);

        const Router& router() const { return _router; }

        Router& router() { return _router; }

        void start_poller();

        // Stores assigned IP's for each session in/out of this lokinet instance
        //  - Reserved local addresses is directly pre-loaded from config
        //  - Persisting address map is directly pre-loaded from config
        address_map<ip_v, NetworkAddress> _local_ip_mapping;

      private:
        std::optional<ip_v> get_next_local_ip();

        std::optional<ip_v> obtain_src_for_remote(const NetworkAddress& remote, bool use_ipv4);

        void send_packet_to_net_if(IPPacket pkt);
    };

}  // namespace llarp::handlers
