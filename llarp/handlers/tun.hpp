#pragma once

#include <llarp/address/ip_packet.hpp>
#include <llarp/address/map.hpp>
#include <llarp/dns/server.hpp>
#include <llarp/net/ip.hpp>
#include <llarp/net/net.hpp>
#include <llarp/service/identity.hpp>
#include <llarp/util/priority_queue.hpp>
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

        vpn::NetworkInterface* get_vpn_interface()
        {
            return _net_if.get();
        }

        std::string_view name() const
        {
            return TUN;
        }

        int rank() const override
        {
            return 0;
        }

        std::string_view resolver_name() const override
        {
            return LOKI_RESOLVER;
        }

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

        // std::shared_ptr<dns::Server> DNS() const override
        // {
        //   return _dns;
        // };

        // INPROGRESS: new API
        // Handles a packet going out of the network through the TUN device
        void handle_outbound_packet(bstring data);
        // Handle a packet coming into the network through the TUN device
        bool handle_inbound_packet(IPPacket pkt);

        // TONUKE: this old bullshit
        // bool handle_inbound_packet(
        //     const service::SessionTag tag, const llarp_buffer_t& pkt, service::ProtocolType t, uint64_t seqno);
        /// handle inbound traffic
        bool handle_write_ip_packet(const llarp_buffer_t& buf, huint128_t src, huint128_t dst, uint64_t seqno);
        /// we got a packet from the user
        void handle_user_packet(llarp::IPPacket pkt);

        /// get the local interface's address
        oxen::quic::Address get_if_addr() const;

        /// we have an interface addr
        bool has_if_addr() const
        {
            return true;
        }

        std::optional<net::TrafficPolicy> get_traffic_policy() const
        {
            return _traffic_policy;
        }

        std::chrono::milliseconds get_path_alignment_timeout() const
        {
            return _path_alignment_timeout;
        }

        /// ip packet against any exit policies we have
        /// returns false if this traffic is disallowed by any of those policies
        /// returns true otherwise
        bool is_allowing_traffic(const IPPacket& pkt) const;

        bool has_mapped_address(const NetworkAddress& addr) const;

        const Router& router() const
        {
            return _router;
        }

        Router& router()
        {
            return _router;
        }

      protected:
        struct WritePacket
        {
            uint64_t seqno;
            IPPacket pkt;

            bool operator>(const WritePacket& other) const
            {
                return seqno > other.seqno;
            }
        };

        address_map<oxen::quic::Address, NetworkAddress> local_ip_mapping;

      private:
        template <typename Addr_t, typename Endpoint_t>
        void send_dns_reply(
            Addr_t addr,
            Endpoint_t ctx,
            std::shared_ptr<dns::Message> query,
            std::function<void(dns::Message)> reply,
            bool sendIPv6)
        {
            if (ctx)
            {
                huint128_t ip = get_ip_for_addr(addr);
                query->answers.clear();
                query->add_IN_reply(ip, sendIPv6);
            }
            else
                query->add_nx_reply();
            reply(*query);
        }

        Router& _router;

        /// dns subsystem for this endpoint
        std::shared_ptr<dns::Server> _dns;

        // std::shared_ptr<auth::AuthPolicy> _auth_policy;

        /// our local address and ip
        oxen::quic::Address _local_addr;
        ip _local_ip;

        /// Our local Network Address holding our network pubkey
        NetworkAddress _local_netaddr;

        /// our network interface's ipv6 address
        oxen::quic::Address _local_ipv6;

        /// next ip address to allocate
        ip _next_ip;

        /// highest ip address to allocate
        ip _max_ip;  // last IP address in the range (add to IPRange class)

        /// our ip range we are using
        IPRange _local_range;
        /// list of strict connect addresses for hooks
        // std::vector<IpAddress> _strict_connect_addrs;
        /// use v6?
        bool _is_ipv6;
        std::string _if_name;

        std::optional<IPRange> _base_ipv6_range = std::nullopt;

        std::shared_ptr<vpn::NetworkInterface> _net_if;

        std::shared_ptr<vpn::PacketRouter> _packet_router;

        std::optional<net::TrafficPolicy> _traffic_policy = std::nullopt;

        /// how long to wait for path alignment
        std::chrono::milliseconds _path_alignment_timeout{30s};

        /// a file to load / store the ephemeral address map to
        std::optional<fs::path> _persisting_addr_file = std::nullopt;

        service::Identity _identity;

        /// for raw packet dns
        std::shared_ptr<vpn::I_Packet_IO> _raw_DNS;
    };

}  // namespace llarp::handlers
