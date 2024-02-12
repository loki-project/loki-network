#pragma once

#include "common.hpp"

#include <llarp/dns/server.hpp>
#include <llarp/ev/ev.hpp>
#include <llarp/net/ip.hpp>
#include <llarp/net/ip_packet_old.hpp>
#include <llarp/net/net.hpp>
#include <llarp/service/handler.hpp>
#include <llarp/service/types.hpp>
#include <llarp/util/priority_queue.hpp>
#include <llarp/util/thread/threading.hpp>
#include <llarp/vpn/packet_router.hpp>
#include <llarp/vpn/platform.hpp>

#include <future>
#include <type_traits>
#include <variant>

/**
  DISCUSS:
    - Q: Where should {Tun,Null}Endpoint live in the heirarchy?

    - Q: Does it make more sense for {Tun,Null}Endpoint to bypass service::Handler and directly
      inherit from PathBuilder?
      - A: Likely. The addition of handlers::RemoteHandler to the inheritance of service::Handler
        and exit::Handler strengthen this argument, as those functionalities are not necessary for
        {Tun,Null}Endpoint.
    - Q: Is EndpointBase necessary? Or is session management outside the scope of {Tun,Null}Endpoint
      - A: Likely not. But will leave it in at the moment. The previous implementation brought in
        EndpointBase via service::Endpoint, and it seems reachability in regards to introsets may
        be important.
*/

namespace llarp::handlers
{
    struct TunEndpoint final : public dns::Resolver_Base,
                               public BaseHandler,
                               public std::enable_shared_from_this<TunEndpoint>
    {
        TunEndpoint(Router& r);
        ~TunEndpoint() override;

        vpn::NetworkInterface* get_vpn_interface() override
        {
            return _net_if.get();
        }

        std::string name() const override
        {
            return "tun"s;
        }

        int rank() const override
        {
            return 0;
        }

        std::string_view resolver_name() const override
        {
            return "lokinet";
        }

        bool maybe_hook_dns(
            std::shared_ptr<dns::PacketSource_Base> source,
            const dns::Message& query,
            const SockAddr_deprecated& to,
            const SockAddr_deprecated& from) override;

        // Reconfigures DNS servers and restarts libunbound with the new servers.
        void reconfigure_dns(std::vector<oxen::quic::Address> servers);

        bool configure(const NetworkConfig& conf, const DnsConfig& dnsConf) override;

        std::string get_if_name() const override;

        StatusObject ExtractStatus() const;

        // std::unordered_map<std::string, std::string>
        // NotifyParams() const override;

        bool supports_ipv6() const override;

        bool should_hook_dns_message(const dns::Message& msg) const;

        bool handle_hooked_dns_message(dns::Message query, std::function<void(dns::Message)> sendreply);

        void tick_tun(llarp_time_t now);

        bool map_address(const service::Address& remote, oxen::quic::Address ip, bool SNode);

        bool start();

        bool stop();

        bool is_snode() const;

        /// set up tun interface, blocking
        bool setup_tun();

        void setup_dns();

        /// overrides Endpoint
        // std::shared_ptr<dns::Server> DNS() const override
        // {
        //   return _dns;
        // };

        /// overrides Endpoint
        bool setup_networking() override;

        /// overrides Endpoint
        bool handle_inbound_packet(
            const service::SessionTag tag, const llarp_buffer_t& pkt, service::ProtocolType t, uint64_t seqno) override;

        /// handle inbound traffic
        bool handle_write_ip_packet(const llarp_buffer_t& buf, huint128_t src, huint128_t dst, uint64_t seqno);

        /// we got a packet from the user
        void handle_user_packet(llarp::net::IP_packet_deprecated pkt);

        // TODO: change this to the new IP type after changing the member
        /// get the local interface's address
        oxen::quic::Address get_if_addr() const /* override */;

        /// we have an interface addr
        bool has_if_addr() const /* override */
        {
            return true;
        }

        bool has_local_ip(const huint128_t& ip) const;

        std::optional<net::TrafficPolicy> get_traffic_policy() const /* override */
        {
            return _traffic_policy;
        }

        std::set<IPRange> get_owned_ranges() const /* override */
        {
            return _owned_ranges;
        }

        llarp_time_t get_path_alignment_timeout() const /* override */
        {
            return _path_alignment_timeout;
        }

        /// ip packet against any exit policies we have
        /// returns false if this traffic is disallowed by any of those policies
        /// returns true otherwise
        bool is_allowing_traffic(const net::IP_packet_deprecated& pkt) const;

        /// get a key for ip address
        std::optional<std::variant<service::Address, RouterID>> get_addr_for_ip(huint128_t ip) const override;

        bool has_mapped_address(const AlignedBuffer<32>& addr) const
        {
            return _addr_to_ip.find(addr) != _addr_to_ip.end();
        }

        /// get ip address for key unconditionally
        huint128_t get_ip_for_addr(std::variant<service::Address, RouterID> addr) override;

       protected:
        struct WritePacket
        {
            uint64_t seqno;
            net::IP_packet_deprecated pkt;

            bool operator>(const WritePacket& other) const
            {
                return seqno > other.seqno;
            }
        };

        /// return true if we have a remote loki address for this ip address
        bool is_ip_mapped(huint128_t ipv4) const;

        /// mark this address as active
        void mark_ip_active(huint128_t ip);

        /// mark this address as active forever
        void mark_ip_active_forever(huint128_t ip);

        /// flush writing ip packets to interface
        void flush_write();

        // TONUKE: errythang buddy
        /// maps ip to key (host byte order)
        std::unordered_map<huint128_t, AlignedBuffer<32>> _ip_to_addr;
        /// maps key to ip (host byte order)
        std::unordered_map<AlignedBuffer<32>, huint128_t> _addr_to_ip;

        /// maps key to true if key is a service node, maps key to false if key is
        /// a hidden service
        // TONUKE: this stupid POS
        std::unordered_map<AlignedBuffer<32>, bool> _is_snode_map;

        /// maps ip address to an exit endpoint, useful when we have multiple exits on a range
        std::unordered_map<huint128_t, service::Address> _exit_to_ip;

       private:
        /// given an ip address that is not mapped locally find the address it shall be forwarded to
        /// optionally provide a custom selection strategy, if none is provided it will choose a
        /// random entry from the available choices
        /// return std::nullopt if we cannot route this address to an exit
        std::optional<service::Address> get_exit_address_for_ip(
            huint128_t ip,
            std::function<service::Address(std::unordered_set<service::Address>)> exitSelectionStrat = nullptr);

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

        /// dns subsystem for this endpoint
        std::shared_ptr<dns::Server> _dns;

        DnsConfig _dns_config;

        // TODO: change the IP's to the variant IP type in address/ip_range.hpp

        /// maps ip address to timestamp last active
        std::unordered_map<huint128_t, llarp_time_t> _ip_activity;
        /// our ip address (host byte order)
        oxen::quic::Address _local_ip;
        /// our network interface's ipv6 address
        IPRange _local_ipv6;

        /// next ip address to allocate (host byte order)
        IPRange _next_ip;
        /// highest ip address to allocate (host byte order)
        IPRange _max_ip;
        /// our ip range we are using
        IPRange _local_range;
        /// list of strict connect addresses for hooks
        // std::vector<IpAddress> _strict_connect_addrs;
        /// use v6?
        bool _use_v6;
        std::string _if_name;

        std::optional<IPRange> _base_address_v6 = std::nullopt;

        std::shared_ptr<vpn::NetworkInterface> _net_if;

        std::shared_ptr<vpn::PacketRouter> _packet_router;

        std::optional<net::TrafficPolicy> _traffic_policy = std::nullopt;
        /// ranges we advetise as reachable
        std::set<IPRange> _owned_ranges;
        /// how long to wait for path alignment
        llarp_time_t _path_alignment_timeout;

        /// a file to load / store the ephemeral address map to
        std::optional<fs::path> _persisting_addr_file = std::nullopt;

        /// for raw packet dns
        std::shared_ptr<vpn::I_Packet_IO> _raw_DNS;
    };

}  // namespace llarp::handlers
