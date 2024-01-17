#pragma once

#include "common.hpp"

#include <llarp/dns/server.hpp>
#include <llarp/ev/ev.hpp>
#include <llarp/net/ip.hpp>
#include <llarp/net/ip_packet.hpp>
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

        vpn::NetworkInterface* GetVPNInterface() override
        {
            return _net_if.get();
        }

        std::string name() const override
        {
            return "tun"s;
        }

        int Rank() const override
        {
            return 0;
        }

        std::string_view ResolverName() const override
        {
            return "lokinet";
        }

        bool MaybeHookDNS(
            std::shared_ptr<dns::PacketSource_Base> source,
            const dns::Message& query,
            const SockAddr& to,
            const SockAddr& from) override;

        // Reconfigures DNS servers and restarts libunbound with the new servers.
        void ReconfigureDNS(std::vector<SockAddr> servers);

        bool configure(const NetworkConfig& conf, const DnsConfig& dnsConf) override;

        std::string GetIfName() const override;

        StatusObject ExtractStatus() const;

        // std::unordered_map<std::string, std::string>
        // NotifyParams() const override;

        bool SupportsV6() const override;

        bool ShouldHookDNSMessage(const dns::Message& msg) const;

        bool HandleHookedDNSMessage(dns::Message query, std::function<void(dns::Message)> sendreply);

        void TickTun(llarp_time_t now);

        bool MapAddress(const service::Address& remote, huint128_t ip, bool SNode);

        bool Start();

        bool stop();

        bool IsSNode() const;

        /// set up tun interface, blocking
        bool SetupTun();

        void SetupDNS();

        /// overrides Endpoint
        // std::shared_ptr<dns::Server> DNS() const override
        // {
        //   return _dns;
        // };

        /// overrides Endpoint
        bool SetupNetworking() override;

        /// overrides Endpoint
        bool HandleInboundPacket(
            const service::SessionTag tag, const llarp_buffer_t& pkt, service::ProtocolType t, uint64_t seqno) override;

        /// handle inbound traffic
        bool handle_write_ip_packet(const llarp_buffer_t& buf, huint128_t src, huint128_t dst, uint64_t seqno);

        /// we got a packet from the user
        void handle_user_packet(llarp::net::IPPacket pkt);

        /// get the local interface's address
        huint128_t GetIfAddr() const /* override */;

        /// we have an interface addr
        bool HasIfAddr() const /* override */
        {
            return true;
        }

        bool HasLocalIP(const huint128_t& ip) const;

        std::optional<net::TrafficPolicy> GetExitPolicy() const /* override */
        {
            return _traffic_policy;
        }

        std::set<IPRange> GetOwnedRanges() const /* override */
        {
            return _owned_ranges;
        }

        llarp_time_t PathAlignmentTimeout() const /* override */
        {
            return _path_alignment_timeout;
        }

        /// ip packet against any exit policies we have
        /// returns false if this traffic is disallowed by any of those policies
        /// returns true otherwise
        bool ShouldAllowTraffic(const net::IPPacket& pkt) const;

        /// get a key for ip address
        std::optional<std::variant<service::Address, RouterID>> ObtainAddrForIP(huint128_t ip) const override;

        bool HasAddress(const AlignedBuffer<32>& addr) const
        {
            return m_AddrToIP.find(addr) != m_AddrToIP.end();
        }

        /// get ip address for key unconditionally
        huint128_t ObtainIPForAddr(std::variant<service::Address, RouterID> addr) override;

       protected:
        struct WritePacket
        {
            uint64_t seqno;
            net::IPPacket pkt;

            bool operator>(const WritePacket& other) const
            {
                return seqno > other.seqno;
            }
        };

        /// return true if we have a remote loki address for this ip address
        bool HasRemoteForIP(huint128_t ipv4) const;

        /// mark this address as active
        void MarkIPActive(huint128_t ip);

        /// mark this address as active forever
        void MarkIPActiveForever(huint128_t ip);

        /// flush writing ip packets to interface
        void FlushWrite();

        /// maps ip to key (host byte order)
        std::unordered_map<huint128_t, AlignedBuffer<32>> m_IPToAddr;
        /// maps key to ip (host byte order)
        std::unordered_map<AlignedBuffer<32>, huint128_t> m_AddrToIP;

        /// maps key to true if key is a service node, maps key to false if key is
        /// a hidden service
        std::unordered_map<AlignedBuffer<32>, bool> m_SNodes;

        /// maps ip address to an exit endpoint, useful when we have multiple exits on a range
        std::unordered_map<huint128_t, service::Address> m_ExitIPToExitAddress;

       private:
        /// given an ip address that is not mapped locally find the address it shall be forwarded to
        /// optionally provide a custom selection strategy, if none is provided it will choose a
        /// random entry from the available choices
        /// return std::nullopt if we cannot route this address to an exit
        std::optional<service::Address> ObtainExitAddressFor(
            huint128_t ip,
            std::function<service::Address(std::unordered_set<service::Address>)> exitSelectionStrat = nullptr);

        template <typename Addr_t, typename Endpoint_t>
        void SendDNSReply(
            Addr_t addr,
            Endpoint_t ctx,
            std::shared_ptr<dns::Message> query,
            std::function<void(dns::Message)> reply,
            bool sendIPv6)
        {
            if (ctx)
            {
                huint128_t ip = ObtainIPForAddr(addr);
                query->answers.clear();
                query->AddINReply(ip, sendIPv6);
            }
            else
                query->AddNXReply();
            reply(*query);
        }

        /// dns subsystem for this endpoint
        std::shared_ptr<dns::Server> _dns;

        DnsConfig _dns_config;

        /// maps ip address to timestamp last active
        std::unordered_map<huint128_t, llarp_time_t> _ip_activity;
        /// our ip address (host byte order)
        huint128_t _local_ip;
        /// our network interface's ipv6 address
        huint128_t _local_ipv6;

        /// next ip address to allocate (host byte order)
        huint128_t _next_ip;
        /// highest ip address to allocate (host byte order)
        huint128_t _max_ip;
        /// our ip range we are using
        llarp::IPRange _local_range;
        /// list of strict connect addresses for hooks
        std::vector<IpAddress> _strict_connect_addrs;
        /// use v6?
        bool _use_v6;
        std::string _if_name;

        std::optional<huint128_t> _base_address_v6;

        std::shared_ptr<vpn::NetworkInterface> _net_if;

        std::shared_ptr<vpn::PacketRouter> _packet_router;

        std::optional<net::TrafficPolicy> _traffic_policy;
        /// ranges we advetise as reachable
        std::set<IPRange> _owned_ranges;
        /// how long to wait for path alignment
        llarp_time_t _path_alignment_timeout;

        /// a file to load / store the ephemeral address map to
        std::optional<fs::path> _persisting_addr_file;

        /// for raw packet dns
        std::shared_ptr<vpn::I_Packet_IO> _raw_DNS;
    };

}  // namespace llarp::handlers
