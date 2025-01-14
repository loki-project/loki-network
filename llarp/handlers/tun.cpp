#include "tun.hpp"

#include <algorithm>
#include <iterator>
#include <variant>
#ifndef _WIN32
#include <sys/socket.h>
#endif

#include <llarp/auth/auth.hpp>
#include <llarp/constants/platform.hpp>
#include <llarp/contact/sns.hpp>
#include <llarp/dns/dns.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/router/route_poker.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging/buffer.hpp>
#include <llarp/util/str.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("tun");

    bool TunEndpoint::maybe_hook_dns(
        std::shared_ptr<dns::PacketSource_Base> source,
        const dns::Message& query,
        const oxen::quic::Address& to,
        const oxen::quic::Address& from)
    {
        if (not should_hook_dns_message(query))
            return false;

        auto job = std::make_shared<dns::QueryJob>(source, query, to, from);
        // if (HandleHookedDNSMessage(query, [job](auto msg) { job->SendReply(msg.ToBuffer()); }))
        //   router().TriggerPump();
        // else
        //   job->Cancel();
        return true;
    }

    /// Intercepts DNS IP packets on platforms where binding to a low port isn't viable.
    /// (windows/macos/ios/android ... aka everything that is not linux... funny that)
    class DnsInterceptor : public dns::PacketSource_Base
    {
        ip_pkt_hook _hook;
        oxen::quic::Address _our_ip;  // maybe should be an IP type...?
        llarp::DnsConfig _config;

      public:
        explicit DnsInterceptor(ip_pkt_hook reply, oxen::quic::Address our_ip, llarp::DnsConfig conf)
            : _hook{std::move(reply)}, _our_ip{std::move(our_ip)}, _config{std::move(conf)}
        {}

        ~DnsInterceptor() override = default;

        void send_to(const oxen::quic::Address& to, const oxen::quic::Address& from, IPPacket data) const override
        {
            if (data.empty())
                return;
            // TOFIX: this
            (void)to;
            (void)from;
            (void)data;
            // _hook(data.make_udp(to, from));
        }

        void stop() override{};

        std::optional<oxen::quic::Address> bound_on() const override { return std::nullopt; }

        bool would_loop(const oxen::quic::Address& to, const oxen::quic::Address& from) const override
        {
            if constexpr (platform::is_apple)
            {
                // DNS on Apple is a bit weird because in order for the NetworkExtension itself to
                // send data through the tunnel we have to proxy DNS requests through Apple APIs
                // (and so our actual upstream DNS won't be set in our resolvers, which is why the
                // vanilla WouldLoop won't work for us).  However when active the mac also only
                // queries the main tunnel IP for DNS, so we consider anything else to be
                // upstream-bound DNS to let it through the tunnel.
                return to != _our_ip;
            }
            else if (auto maybe_addr = _config._query_bind)
            {
                const auto& addr = *maybe_addr;
                // omit traffic to and from our dns socket
                return addr == to or addr == from;
            }
            return false;
        }
    };

    class TunDNS : public dns::Server
    {
        const TunEndpoint* _tun;
        std::optional<oxen::quic::Address> _query_bind;
        oxen::quic::Address _our_ip;

      public:
        std::shared_ptr<dns::PacketSource_Base> pkt_source;

        ~TunDNS() override = default;

        explicit TunDNS(TunEndpoint* ep, const llarp::DnsConfig& conf)
            : dns::Server{ep->router().loop(), conf, 0},
              _tun{ep},
              _query_bind{conf._query_bind},
              _our_ip{ep->get_if_addr()}
        {
            if (_query_bind)
                _our_ip.set_port(_query_bind->port());
        }

        std::shared_ptr<dns::PacketSource_Base> make_packet_source_on(
            const oxen::quic::Address&, const llarp::DnsConfig& conf) override
        {
            (void)_tun;
            auto ptr = std::make_shared<DnsInterceptor>(
                [](IPPacket pkt) {
                    (void)pkt;
                    // ep->handle_write_ip_packet(pkt.ConstBuffer(), pkt.srcv6(), pkt.dstv6(), 0);
                },
                _our_ip,
                conf);
            pkt_source = ptr;
            return ptr;
        }
    };

    TunEndpoint::TunEndpoint(Router& r) : _router{r}
    {
        _packet_router =
            std::make_shared<vpn::PacketRouter>([this](IPPacket pkt) { handle_outbound_packet(std::move(pkt)); });
    }

    void TunEndpoint::setup_dns()
    {
        log::debug(logcat, "{} setting up DNS...", name());

        auto& dns_config = _router.config()->dns;
        const auto& info = get_vpn_interface()->interface_info();

        if (dns_config.l3_intercept)
        {
            auto dns = std::make_shared<TunDNS>(this, dns_config);
            _dns = dns;

            uint16_t p = 53;

            while (p < 100)
            {
                try
                {
                    _packet_router->add_udp_handler(p, [this, dns](IPPacket pkt) {
                        auto dns_pkt_src = dns->pkt_source;

                        if (dns->maybe_handle_packet(
                                std::move(dns_pkt_src), pkt.destination(), pkt.source(), std::move(pkt)))
                            return;

                        handle_outbound_packet(std::move(pkt));
                    });
                }
                catch (const std::exception& e)
                {
                    if (p += 1; p >= 100)
                        throw std::runtime_error{"Failed to port map udp handler: {}"_format(e.what())};
                }
            }
        }
        else
            _dns = std::make_shared<dns::Server>(_router.loop(), dns_config, info.index);

        _dns->add_resolver(weak_from_this());
        _dns->start();

        if (dns_config.l3_intercept)
        {
            if (auto vpn = _router.vpn_platform())
            {
                // get the first local address we know of
                std::optional<oxen::quic::Address> localaddr;

                for (auto res : _dns->get_all_resolvers())
                {
                    if (auto ptr = res.lock())
                    {
                        localaddr = ptr->get_local_addr();

                        if (localaddr)
                            break;
                    }
                }
                if (platform::is_windows)
                {
                    // auto dns_io = vpn->create_packet_io(0, localaddr);
                    // router().loop()->add_ticker([dns_io, handler = m_PacketRouter]() {
                    //   net::IPPacket pkt = dns_io->ReadNextPacket();
                    //   while (not pkt.empty())
                    //   {
                    //     handler->HandleIPPacket(std::move(pkt));
                    //     pkt = dns_io->ReadNextPacket();
                    //   }
                    // });
                    // m_RawDNS = dns_io;
                }

                (void)vpn;
            }

            if (_raw_DNS)
                _raw_DNS->Start();
        }
    }

    nlohmann::json TunEndpoint::ExtractStatus() const
    {
        // auto obj = service::Endpoint::ExtractStatus();
        // obj["ifaddr"] = m_OurRange.to_string();
        // obj["ifname"] = m_IfName;

        // std::vector<std::string> upstreamRes;
        // for (const auto& ent : m_DnsConfig.upstream_dns)
        //   upstreamRes.emplace_back(ent.to_string());
        // obj["ustreamResolvers"] = upstreamRes;

        // std::vector<std::string> localRes;
        // for (const auto& ent : m_DnsConfig.bind_addr)
        //   localRes.emplace_back(ent.to_string());
        // obj["localResolvers"] = localRes;

        // // for backwards compat
        // if (not m_DnsConfig.bind_addr.empty())
        //   obj["localResolver"] = localRes[0];

        // nlohmann::json ips{};
        // for (const auto& item : m_IPActivity)
        // {
        //   nlohmann::json ipObj{{"lastActive", to_json(item.second)}};
        //   std::string remoteStr;
        //   AlignedBuffer<32> addr = m_IPToAddr.at(item.first);
        //   if (m_SNodes.at(addr))
        //     remoteStr = RouterID(addr.as_array()).to_string();
        //   else
        //     remoteStr = service::Address(addr.as_array()).to_string();
        //   ipObj["remote"] = remoteStr;
        //   std::string ipaddr = item.first.to_string();
        //   ips[ipaddr] = ipObj;
        // }
        // obj["addrs"] = ips;
        // obj["ourIP"] = m_OurIP.to_string();
        // obj["nextIP"] = m_NextIP.to_string();
        // obj["maxIP"] = m_MaxIP.to_string();
        // return obj;
        return {};
    }

    void TunEndpoint::reconfigure_dns(std::vector<oxen::quic::Address> servers)
    {
        if (_dns)
        {
            for (auto weak : _dns->get_all_resolvers())
            {
                if (auto ptr = weak.lock())
                    ptr->reset_resolver(servers);
            }
        }
    }

    /** DISCUSS: Can the auth objects be further simplified?
        - In the original implementation, the AuthPolicy async logic was for the instance receiving the connection
            request to execute its aynchronous logic and queue the authentication job

        Static Token Auth:
        - In the re-designed auth paradigm, static tokens are either independantly coordinated with the exit/service
            operator
        - The session initiator will automatically include any static tokens that are either (A) loaded into the
            config mapping or (B) passed to the lokinet-vpn cli utility
            - As a result, the session initiator doesn't necessarily need an AuthPolicy object

        RPC Auth:
        - Why can't the functionality of this be entirely subsumed by the RPCClient?
            - If the config specifies the auth_type as RPC plus
    */
    void TunEndpoint::configure()
    {
        return _router.loop()->call_get([&]() {
            log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

            auto& net_conf = _router.config()->network;

            _exit_policy = net_conf.traffic_policy;
            _base_ipv6_range = net_conf._base_ipv6_range;

            if (net_conf.path_alignment_timeout)
            {
                if (is_service_node())
                    throw std::runtime_error{"Service nodes cannot specify path alignment timeout!"};

                _path_alignment_timeout = *net_conf.path_alignment_timeout;
            }

            _if_name = *net_conf._if_name;
            _local_range = *net_conf._local_ip_range;
            _local_addr = *net_conf._local_addr;
            _local_base_ip = *net_conf._local_base_ip;

            ipv6_enabled = not _local_range.is_ipv4();
            if (ipv6_enabled and not net_conf.enable_ipv6)
                throw std::runtime_error{
                    "Config must explicitly enable IPv6 to use local range: {}"_format(_local_range)};

            if (net_conf.addr_map_persist_file)
            {
                _persisting_addr_file = net_conf.addr_map_persist_file;
                persist_addrs = true;
            }

            if (not net_conf._reserved_local_ips.empty())
            {
                for (auto& [remote, local] : net_conf._reserved_local_ips)
                {
                    _local_ip_mapping.insert_or_assign(local, remote);
                }
            }

            log::debug(logcat, "Tun constructing IPRange iterator on local range: {}", _local_range);
            _local_range_iterator = IPRangeIterator(_local_range);

            _local_netaddr = NetworkAddress::from_pubkey(_router.local_rid(), not _router.is_service_node());
            _local_ip_mapping.insert_or_assign(_local_range.net_ip(), std::move(_local_netaddr));

            vpn::InterfaceInfo info;
            info.ifname = _if_name;
            info.if_info = net_conf._if_info;
            info.addrs.emplace_back(_local_range);

            if (net_conf.enable_ipv6 and _base_ipv6_range)
            {
                log::info(logcat, "{} using ipv6 range:{}", name(), *_base_ipv6_range);
                info.addrs.emplace_back(*_base_ipv6_range);
            }

            log::debug(logcat, "{} setting up network...", name());

            _local_ipv6 = ipv6_enabled ? _local_addr : _local_addr.mapped_ipv4_as_ipv6();

            if (ipv6_enabled)
            {
                if constexpr (not llarp::platform::is_apple)
                {
                    if (auto maybe = router().net().get_interface_ipv6_addr(_if_name))
                    {
                        _local_ipv6 = *maybe;
                    }
                }
            }

            log::info(
                logcat, "{} has interface ipv4 address ({}) with ipv6 address ({})", name(), _local_addr, _local_ipv6);

            _net_if = router().vpn_platform()->create_interface(std::move(info), &_router);
            _if_name = _net_if->interface_info().ifname;

            log::info(logcat, "{} got network interface:{}", name(), _if_name);

            auto pkt_hook = [this]() mutable {
                for (auto pkt = _net_if->read_next_packet(); not pkt.empty(); pkt = _net_if->read_next_packet())
                {
                    log::trace(logcat, "packet router receiving {}", pkt.info_line());
                    _packet_router->handle_ip_packet(std::move(pkt));
                }
            };

            if (_poller = router().loop()->add_network_interface(_net_if, std::move(pkt_hook)); not _poller)
            {
                auto err = "{} failed to add network interface!"_format(name());
                log::error(logcat, "{}", err);
                throw std::runtime_error{std::move(err)};
            }

            // if (auto* quic = GetQUICTunnel())
            // {
            // TODO:
            // quic->listen([this](std::string_view, uint16_t port) {
            //   return llarp::SockAddr{net::TruncateV6(GetIfAddr()), huint16_t{port}};
            // });
            // }

            setup_dns();
        });
    }

    static bool is_random_snode(const dns::Message& msg) { return msg.questions[0].IsName("random.snode"); }

    static bool is_localhost_loki(const dns::Message& msg) { return msg.questions[0].IsLocalhost(); }

    static dns::Message& clear_dns_message(dns::Message& msg)
    {
        msg.authorities.resize(0);
        msg.additional.resize(0);
        msg.answers.resize(0);
        msg.hdr_fields &= ~dns::flags_RCODENameError;
        return msg;
    }

    bool TunEndpoint::handle_hooked_dns_message(dns::Message msg, std::function<void(dns::Message)> reply)
    {
        (void)msg;
        (void)reply;
        // auto ReplyToSNodeDNSWhenReady = [this, reply](RouterID snode, auto msg, bool isV6) ->
        // bool {
        //   return EnsurePathToSNode(
        //       snode,
        //       [this, snode, msg, reply, isV6](
        //           const RouterID&,
        //           std::shared_ptr<session::BaseSession> s,
        //           [[maybe_unused]] SessionTag tag) {
        //         SendDNSReply(snode, s, msg, reply, isV6);
        //       });
        // };
        // auto ReplyToLokiDNSWhenReady = [this, reply, timeout = PathAlignmentTimeout()](
        //                                    service::Address addr, auto msg, bool isV6) -> bool {
        //   using service::Address;
        //   using service::OutboundContext;
        //   if (HasInboundConvo(addr))
        //   {
        //     // if we have an inbound convo to this address don't mark as outbound so we don't
        //     have a
        //     // state race this codepath is hit when an application verifies that reverse and
        //     forward
        //     // dns records match for an inbound session
        //     SendDNSReply(addr, this, msg, reply, isV6);
        //     return true;
        //   }
        //   MarkAddressOutbound(addr);
        //   return EnsurePathToService(
        //       addr,
        //       [this, addr, msg, reply, isV6](const Address&, OutboundContext* ctx) {
        //         SendDNSReply(addr, ctx, msg, reply, isV6);
        //       },
        //       timeout);
        // };

        // auto ReplyToDNSWhenReady = [ReplyToLokiDNSWhenReady, ReplyToSNodeDNSWhenReady](
        //                                std::string name, auto msg, bool isV6) {
        //   if (auto saddr = service::Address(); saddr.FromString(name))
        //     ReplyToLokiDNSWhenReady(saddr, msg, isV6);

        //   if (auto rid = RouterID(); rid.from_snode_address(name))
        //     ReplyToSNodeDNSWhenReady(rid, msg, isV6);
        // };

        // auto ReplyToLokiSRVWhenReady = [this, reply, timeout = PathAlignmentTimeout()](
        //                                    service::Address addr, auto msg) -> bool {
        //   using service::Address;
        //   using service::OutboundContext;
        //   // TODO: how do we handle SRV record lookups for inbound sessions?
        //   MarkAddressOutbound(addr);
        //   return EnsurePathToService(
        //       addr,
        //       [msg, addr, reply](const Address&, OutboundContext* ctx) {
        //         if (ctx == nullptr)
        //           return;

        //         const auto& introset = ctx->GetCurrentIntroSet();
        //         msg->AddSRVReply(introset.GetMatchingSRVRecords(addr.subdomain));
        //         reply(*msg);
        //       },
        //       timeout);
        // };

        // if (msg.answers.size() > 0)
        // {
        //   const auto& answer = msg.answers[0];
        //   if (answer.HasCNameForTLD(".snode"))
        //   {
        //     llarp_buffer_t buf(answer.rData);
        //     auto qname = dns::DecodeName(&buf, true);
        //     if (not qname)
        //       return false;
        //     RouterID addr;
        //     if (not addr.from_snode_address(*qname))
        //       return false;
        //     auto replyMsg = std::make_shared<dns::Message>(clear_dns_message(msg));
        //     return ReplyToSNodeDNSWhenReady(addr, std::move(replyMsg), false);
        //   }
        //   else if (answer.HasCNameForTLD(".loki"))
        //   {
        //     llarp_buffer_t buf(answer.rData);
        //     auto qname = dns::DecodeName(&buf, true);
        //     if (not qname)
        //       return false;

        //     service::Address addr;
        //     if (not addr.FromString(*qname))
        //       return false;

        //     auto replyMsg = std::make_shared<dns::Message>(clear_dns_message(msg));
        //     return ReplyToLokiDNSWhenReady(addr, replyMsg, false);
        //   }
        // }
        // if (msg.questions.size() != 1)
        // {
        //   log::warning(logcat, "bad number of dns questions: {}", msg.questions.size());
        //   return false;
        // }
        // std::string qname = msg.questions[0].Name();
        // const auto nameparts = split(qname, ".");
        // std::string ons_name;
        // if (nameparts.size() >= 2 and ends_with(qname, ".loki"))
        // {
        //   ons_name = nameparts[nameparts.size() - 2];
        //   ons_name += ".loki"sv;
        // }
        // if (msg.questions[0].qtype == dns::qTypeTXT)
        // {
        //   RouterID snode;
        //   if (snode.from_snode_address(qname))
        //   {
        //     if (auto rc = router().node_db()->get_rc(snode))
        //       msg.AddTXTReply(std::string{rc->view()});
        //     else
        //       msg.AddNXReply();
        //     reply(msg);

        //     return true;
        //   }

        //   if (msg.questions[0].IsLocalhost() and msg.questions[0].HasSubdomains())
        //   {
        //     const auto subdomain = msg.questions[0].Subdomains();
        //     if (subdomain == "exit")
        //     {
        //       if (HasExit())
        //       {
        //         std::string s;
        //         _exit_map.ForEachEntry([&s](const auto& range, const auto& exit) {
        //           fmt::format_to(std::back_inserter(s), "{}={}; ", range, exit);
        //         });
        //         msg.AddTXTReply(std::move(s));
        //       }
        //       else
        //       {
        //         msg.AddNXReply();
        //       }
        //     }
        //     else if (subdomain == "netid")
        //     {
        //       msg.AddTXTReply(fmt::format("netid={};", RelayContact::ACTIVE_NETID));
        //     }
        //     else
        //     {
        //       msg.AddNXReply();
        //     }
        //   }
        //   else
        //   {
        //     msg.AddNXReply();
        //   }

        //   reply(msg);
        // }
        // else if (msg.questions[0].qtype == dns::qTypeMX)
        // {
        //   // mx record
        //   service::Address addr;
        //   if (addr.FromString(qname, ".loki") || addr.FromString(qname, ".snode")
        //       || is_random_snode(msg) || is_localhost_loki(msg))
        //   {
        //     msg.AddMXReply(qname, 1);
        //   }
        //   else if (service::is_valid_name(ons_name))
        //   {
        //     lookup_name(
        //         ons_name, [msg, ons_name, reply](std::string name_result, bool success) mutable {
        //           if (success)
        //           {
        //             msg.AddMXReply(name_result, 1);
        //           }
        //           else
        //             msg.AddNXReply();

        //           reply(msg);
        //         });

        //     return true;
        //   }
        //   else
        //     msg.AddNXReply();
        //   reply(msg);
        // }
        // else if (msg.questions[0].qtype == dns::qTypeCNAME)
        // {
        //   if (is_random_snode(msg))
        //   {
        //     if (auto random = router().GetRandomGoodRouter())
        //     {
        //       msg.AddCNAMEReply(random->to_string(), 1);
        //     }
        //     else
        //       msg.AddNXReply();
        //   }
        //   else if (msg.questions[0].IsLocalhost() and msg.questions[0].HasSubdomains())
        //   {
        //     const auto subdomain = msg.questions[0].Subdomains();
        //     if (subdomain == "exit" and HasExit())
        //     {
        //       _exit_map.ForEachEntry(
        //           [&msg](const auto&, const auto& exit) { msg.AddCNAMEReply(exit.to_string(), 1);
        //           });
        //     }
        //     else
        //     {
        //       msg.AddNXReply();
        //     }
        //   }
        //   else if (is_localhost_loki(msg))
        //   {
        //     size_t counter = 0;
        //     context->ForEachService(
        //         [&](const std::string&, const std::shared_ptr<service::Endpoint>& service) ->
        //         bool {
        //           const service::Address addr = service->GetIdentity().pub.Addr();
        //           msg.AddCNAMEReply(addr.to_string(), 1);
        //           ++counter;
        //           return true;
        //         });
        //     if (counter == 0)
        //       msg.AddNXReply();
        //   }
        //   else
        //     msg.AddNXReply();
        //   reply(msg);
        // }
        // else if (msg.questions[0].qtype == dns::qTypeA || msg.questions[0].qtype ==
        // dns::qTypeAAAA)
        // {
        //   const bool isV6 = msg.questions[0].qtype == dns::qTypeAAAA;
        //   const bool isV4 = msg.questions[0].qtype == dns::qTypeA;
        //   llarp::service::Address addr;
        //   if (isV6 && !SupportsV6())
        //   {  // empty reply but not a NXDOMAIN so that client can retry IPv4
        //     msg.AddNSReply("localhost.loki.");
        //   }
        //   // on MacOS this is a typeA query
        //   else if (is_random_snode(msg))
        //   {
        //     if (auto random = router().GetRandomGoodRouter())
        //     {
        //       msg.AddCNAMEReply(random->to_string(), 1);
        //       return ReplyToSNodeDNSWhenReady(*random, std::make_shared<dns::Message>(msg),
        //       isV6);
        //     }

        //     msg.AddNXReply();
        //   }
        //   else if (is_localhost_loki(msg))
        //   {
        //     const bool lookingForExit = msg.questions[0].Subdomains() == "exit";
        //     huint128_t ip = GetIfAddr();
        //     if (ip.h)
        //     {
        //       if (lookingForExit)
        //       {
        //         if (HasExit())
        //         {
        //           _exit_map.ForEachEntry(
        //               [&msg](const auto&, const auto& exit) { msg.AddCNAMEReply(exit.to_string());
        //               });
        //           msg.AddINReply(ip, isV6);
        //         }
        //         else
        //         {
        //           msg.AddNXReply();
        //         }
        //       }
        //       else
        //       {
        //         msg.AddCNAMEReply(_identity.pub.Name(), 1);
        //         msg.AddINReply(ip, isV6);
        //       }
        //     }
        //     else
        //     {
        //       msg.AddNXReply();
        //     }
        //   }
        //   else if (addr.FromString(qname, ".loki"))
        //   {
        //     if (isV4 && SupportsV6())
        //     {
        //       msg.hdr_fields |= dns::flags_QR | dns::flags_AA | dns::flags_RA;
        //     }
        //     else
        //     {
        //       return ReplyToLokiDNSWhenReady(addr, std::make_shared<dns::Message>(msg), isV6);
        //     }
        //   }
        //   else if (addr.FromString(qname, ".snode"))
        //   {
        //     if (isV4 && SupportsV6())
        //     {
        //       msg.hdr_fields |= dns::flags_QR | dns::flags_AA | dns::flags_RA;
        //     }
        //     else
        //     {
        //       return ReplyToSNodeDNSWhenReady(
        //           addr.as_array(), std::make_shared<dns::Message>(msg), isV6);
        //     }
        //   }
        //   else if (service::is_valid_name(ons_name))
        //   {
        //     lookup_name(
        //         ons_name,
        //         [msg = std::make_shared<dns::Message>(msg),
        //          name = Name(),
        //          ons_name,
        //          isV6,
        //          reply,
        //          ReplyToDNSWhenReady](std::string name_result, bool success) mutable {
        //           if (not success)
        //           {
        //             log::warning(logcat, "{} (ONS name: {}) not resolved", name, ons_name);
        //             msg->AddNXReply();
        //             reply(*msg);
        //           }

        //           ReplyToDNSWhenReady(name_result, msg, isV6);
        //         });
        //     return true;
        //   }
        //   else
        //     msg.AddNXReply();

        //   reply(msg);
        // }
        // else if (msg.questions[0].qtype == dns::qTypePTR)
        // {
        //   // reverse dns
        //   if (auto ip = dns::DecodePTR(msg.questions[0].qname))
        //   {
        //     if (auto maybe = ObtainAddrForIP(*ip))
        //     {
        //       var::visit([&msg](auto&& result) { msg.AddAReply(result.to_string()); }, *maybe);
        //       reply(msg);
        //       return true;
        //     }
        //   }

        //   msg.AddNXReply();
        //   reply(msg);
        //   return true;
        // }
        // else if (msg.questions[0].qtype == dns::qTypeSRV)
        // {
        //   auto srv_for = msg.questions[0].Subdomains();
        //   auto name = msg.questions[0].qname;
        //   if (is_localhost_loki(msg))
        //   {
        //     msg.AddSRVReply(intro_set().GetMatchingSRVRecords(srv_for));
        //     reply(msg);
        //     return true;
        //   }
        //   LookupServiceAsync(
        //       name,
        //       srv_for,
        //       [reply, msg = std::make_shared<dns::Message>(std::move(msg))](auto records) {
        //         if (records.empty())
        //         {
        //           msg->AddNXReply();
        //         }
        //         else
        //         {
        //           msg->AddSRVReply(records);
        //         }
        //         reply(*msg);
        //       });
        //   return true;
        // }
        // else
        // {
        //   msg.AddNXReply();
        //   reply(msg);
        // }
        return true;
    }

    bool TunEndpoint::supports_ipv6() const { return ipv6_enabled; }

    // FIXME: pass in which question it should be addressing
    bool TunEndpoint::should_hook_dns_message(const dns::Message& msg) const
    {
        // llarp::service::Address addr;
        if (msg.questions.size() == 1)
        {
            /// hook every .loki
            if (msg.questions[0].HasTLD(".loki"))
                return true;
            /// hook every .snode
            if (msg.questions[0].HasTLD(".snode"))
                return true;
            // hook any ranges we own
            if (msg.questions[0].qtype == llarp::dns::qTypePTR)
            {
                if (auto ip = dns::DecodePTR(msg.questions[0].qname))
                    return _local_range.contains(*ip);
                return false;
            }
        }
        for (const auto& answer : msg.answers)
        {
            if (answer.HasCNameForTLD(".loki"))
                return true;
            if (answer.HasCNameForTLD(".snode"))
                return true;
        }
        return false;
    }

    std::string TunEndpoint::get_if_name() const { return _if_name; }

    bool TunEndpoint::is_service_node() const { return _router.is_service_node(); }

    bool TunEndpoint::is_exit_node() const { return _router.is_exit_node(); }

    bool TunEndpoint::stop()
    {
        // stop vpn tunnel
        if (_net_if)
            _net_if->Stop();
        if (_raw_DNS)
            _raw_DNS->Stop();

        // save address map if applicable
        if (_persisting_addr_file and not platform::is_android)
        {
            const auto& file = *_persisting_addr_file;
            log::debug(logcat, "{} saving address map to {}", name(), file);
            // if (auto maybe = util::OpenFileStream<fs::ofstream>(file, std::ios_base::binary))
            // {
            //   std::map<std::string, std::string> addrmap;
            //   for (const auto& [ip, addr] : m_IPToAddr)
            //   {
            //     if (not m_SNodes.at(addr))
            //     {
            //       const service::Address a{addr.as_array()};
            //       if (HasInboundConvo(a))
            //         addrmap[ip.to_string()] = a.to_string();
            //     }
            //   }
            //   const auto data = oxenc::bt_serialize(addrmap);
            //   maybe->write(data.data(), data.size());
            // }
        }

        if (_dns)
            _dns->stop();

        return true;
    }

    std::optional<ip_v> TunEndpoint::get_next_local_ip()
    {
        // if our IP range is exhausted, we loop back around to see if any have been unmapped from terminated sessions;
        // we only want to reset the iterator and loop back through once though
        bool has_reset = false;

        do
        {
            // this will be std::nullopt if IP range is exhausted OR the IP incrementing overflowed (basically equal)
            if (auto maybe_next_ip = _local_range_iterator.next_ip(); maybe_next_ip)
            {
                if (not _local_ip_mapping.has_local(*maybe_next_ip))
                    return maybe_next_ip;
                // local IP is already assigned; try again
                continue;
            }

            if (not has_reset)
            {
                log::debug(logcat, "Resetting IP range iterator for range: {}...", _local_range);
                _local_range_iterator.reset();
                has_reset = true;
            }
            else
                break;
        } while (true);

        return std::nullopt;
    }

    std::optional<ip_v> TunEndpoint::map_session_to_local_ip(const NetworkAddress& remote)
    {
        std::optional<ip_v> ret = std::nullopt;

        // first: check if we have a config value for this remote
        if (auto maybe_ip = _local_ip_mapping.get_local_from_remote(remote); maybe_ip)
        {
            ret = maybe_ip;
            log::debug(
                logcat,
                "Local IP for session to remote ({}) pre-loaded from config: {}",
                remote,
                std::holds_alternative<ipv4>(*maybe_ip) ? std::get<ipv4>(*maybe_ip).to_string()
                                                        : std::get<ipv6>(*maybe_ip).to_string());
        }
        else
        {
            // We need to check that we both have a valid IP in our local range and that it is not already pre-assigned
            // to a remote from the config
            if (auto maybe_next_ip = get_next_local_ip(); maybe_next_ip)
            {
                ret = maybe_next_ip;
                _local_ip_mapping.insert_or_assign(*maybe_next_ip, remote);

                log::debug(
                    logcat,
                    "Local IP for session to remote ({}) assigned: {}",
                    remote,
                    std::holds_alternative<ipv4>(*maybe_next_ip) ? std::get<ipv4>(*maybe_next_ip).to_string()
                                                                 : std::get<ipv6>(*maybe_next_ip).to_string());
            }
            else
                log::critical(logcat, "TUN device failed to assign local private IP for session to remote: {}", remote);
        }

        return ret;
    }

    void TunEndpoint::unmap_session_to_local_ip(const NetworkAddress& remote)
    {
        if (_local_ip_mapping.has_remote(remote))
        {
            _local_ip_mapping.unmap(remote);
            log::debug(logcat, "TUN device unmapped session to remote: {}", remote);
        }
        else
        {
            log::debug(logcat, "TUN device could not unmap session (remote: {})", remote);
        }
    }

    // handles an outbound packet going OUT from user -> network
    void TunEndpoint::handle_outbound_packet(IPPacket pkt)
    {
        ip_v src, dest;
        auto pkt_is_ipv4 = pkt.is_ipv4();

        log::debug(logcat, "outbound packet: {}: {}", pkt.info_line(), buffer_printer{pkt.uview()});

        if (pkt_is_ipv4)
        {
            src = pkt.source_ipv4();
            dest = pkt.dest_ipv4();
        }
        else
        {
            src = pkt.source_ipv6();
            dest = pkt.dest_ipv6();
        }

        log::trace(logcat, "src:{}, dest:{}", src, dest);

        if constexpr (llarp::platform::is_apple)
        {
            if (ip_equals_address(dest, _local_addr, pkt_is_ipv4))
            {
                rewrite_and_send_packet(std::move(pkt), src, dest);
                return;
            }
        }

        // we pass `dest` because that is our local private IP on the outgoing IPPacket
        if (auto maybe_remote = _local_ip_mapping.get_remote_from_local(dest))
        {
            auto& remote = *maybe_remote;
            pkt.clear_addresses();

            if (auto session = _router.session_endpoint()->get_session(remote))
            {
                log::info(logcat, "Dispatching outbound {}B packet for session (remote: {})", pkt.size(), remote);
                session->send_path_data_message(std::move(pkt).steal_payload());
            }
            else
                log::info(logcat, "Could not find session (remote: {}) for outbound packet!", remote);
        }
        else
            log::debug(logcat, "Could not find remote for route {}", pkt.info_line());
    }

    std::optional<ip_v> TunEndpoint::obtain_src_for_remote(const NetworkAddress& remote, bool use_ipv4)
    {
        if (auto maybe_src = _local_ip_mapping.get_local_from_remote(remote))
        {
            if (std::holds_alternative<ipv4>(*maybe_src))
            {
                if (use_ipv4)
                    return *maybe_src;
                return oxen::quic::Address{std::get<ipv4>(*maybe_src)}.to_ipv6();
            }

            if (use_ipv4)
                return oxen::quic::Address{std::get<ipv6>(*maybe_src)}.to_ipv4();
            return *maybe_src;
        }

        log::warning(logcat, "Unable to find src IP for inbound packet from remote: {}", remote);
        return std::nullopt;
    }

    void TunEndpoint::send_packet_to_net_if(IPPacket pkt)
    {
        _router.loop()->call([this, pkt = std::move(pkt)]() mutable { _net_if->write_packet(std::move(pkt)); });
    }

    void TunEndpoint::rewrite_and_send_packet(IPPacket&& pkt, ip_v src, ip_v dest)
    {
        if (pkt.is_ipv4())
            pkt.update_ipv4_address(std::get<ipv4>(src), std::get<ipv4>(dest));
        else
            pkt.update_ipv6_address(std::get<ipv6>(src), std::get<ipv6>(dest));

        log::trace(logcat, "Rewritten packet: {}: {}", pkt.info_line(), buffer_printer{pkt.uview()});
        send_packet_to_net_if(std::move(pkt));
    }

    // handles an inbound packet coming IN from network -> user
    bool TunEndpoint::handle_inbound_packet(
        IPPacket pkt, NetworkAddress remote, bool is_exit_session, bool is_outbound_session)
    {
        ip_v src, dest;

        auto pkt_is_ipv4 = pkt.is_ipv4();

        if (is_exit_session and is_outbound_session)
        {
            log::info(logcat, "inbound exit session pkt: {}", pkt.info_line());
            // we are receiving traffic from a session to a remote exit node
            if (pkt_is_ipv4)
            {
                src = pkt.source_ipv4();
                dest = _local_addr.to_ipv4();
            }
            else
            {
                src = pkt.source_ipv6();
                dest = _local_ipv6.to_ipv6();
            }

            assert(remote.is_client());

            auto maybe_remote = _local_ip_mapping.get_remote_from_local(src);

            if (not maybe_remote)
            {
                log::info(logcat, "Could not find mapping of local IP (ip:{}) for session to remote: {}", src, remote);
                return false;
            }
            if (*maybe_remote != remote)
            {
                log::info(
                    logcat,
                    "Internal mapping of local IP (ip:{}, remote:{}) did not match inbound packet from remote: {}",
                    src,
                    *maybe_remote,
                    remote);
                return false;
            }
        }
        else
        {
            if (is_exit_session and not is_outbound_session)
            {
                log::info(logcat, "inbound exit session pkt: {}", pkt.info_line());
                // we are receiving traffic from a session to a local exit node
                if (not _exit_policy->allow_ip_traffic(pkt))
                    return false;

                if (pkt_is_ipv4)
                    dest = pkt.dest_ipv4();
                else
                    dest = pkt.dest_ipv6();
            }
            else
            {
                log::info(logcat, "inbound service session pkt: {}", pkt.info_line());
                // we are receiving hidden service traffic
                if (pkt_is_ipv4)
                    dest = _local_addr.to_ipv4();
                else
                    dest = _local_ipv6.to_ipv6();
            }

            if (auto maybe_src = obtain_src_for_remote(remote, pkt_is_ipv4))
                src = std::move(*maybe_src);
            else
                return false;
        }

        log::trace(logcat, "src:{}, dest:{}", src, dest);

        rewrite_and_send_packet(std::move(pkt), src, dest);

        return true;
    }

    void TunEndpoint::start_poller()
    {
        if (not _poller->start())
            throw std::runtime_error{"TUN failed to start FD poller!"};
        log::debug(logcat, "TUN successfully started FD poller!");
    }

    bool TunEndpoint::is_allowing_traffic(const IPPacket& pkt) const
    {
        return _exit_policy ? _exit_policy->allow_ip_traffic(pkt) : true;
    }

    bool TunEndpoint::has_mapping_to_remote(const NetworkAddress& addr) const
    {
        return _local_ip_mapping.has_remote(addr);
    }

    std::optional<ip_v> TunEndpoint::get_mapped_ip(const NetworkAddress& addr)
    {
        return _local_ip_mapping.get_local_from_remote(addr);
    }

    oxen::quic::Address TunEndpoint::get_if_addr() const { return _local_addr; }

    TunEndpoint::~TunEndpoint() = default;

}  // namespace llarp::handlers
