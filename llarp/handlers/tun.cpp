#include "tun.hpp"

#include <algorithm>
#include <iterator>
#include <variant>
#ifndef _WIN32
#include <sys/socket.h>
#endif

#include <llarp/auth/auth.hpp>
#include <llarp/constants/platform.hpp>
#include <llarp/dns/dns.hpp>
#include <llarp/ev/ev.hpp>
#include <llarp/net/net.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/router/route_poker.hpp>
#include <llarp/router/router.hpp>
#include <llarp/service/endpoint_state.hpp>
#include <llarp/service/name.hpp>
#include <llarp/service/types.hpp>
#include <llarp/util/str.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("tun");

    bool TunEndpoint::MaybeHookDNS(
        std::shared_ptr<dns::PacketSource_Base> source,
        const dns::Message& query,
        const SockAddr& to,
        const SockAddr& from)
    {
        if (not ShouldHookDNSMessage(query))
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
        std::function<void(net::IPPacket)> m_Reply;
        net::ipaddr_t m_OurIP;
        llarp::DnsConfig m_Config;

       public:
        explicit DnsInterceptor(std::function<void(net::IPPacket)> reply, net::ipaddr_t our_ip, llarp::DnsConfig conf)
            : m_Reply{std::move(reply)}, m_OurIP{std::move(our_ip)}, m_Config{std::move(conf)}
        {}

        ~DnsInterceptor() override = default;

        void SendTo(const SockAddr& to, const SockAddr& from, OwnedBuffer buf) const override
        {
            auto pkt = net::IPPacket::make_udp(from, to, std::move(buf));

            if (pkt.empty())
                return;
            m_Reply(std::move(pkt));
        }

        void Stop() override{};

        std::optional<SockAddr> BoundOn() const override
        {
            return std::nullopt;
        }

        bool WouldLoop(const SockAddr& to, const SockAddr& from) const override
        {
            if constexpr (platform::is_apple)
            {
                // DNS on Apple is a bit weird because in order for the NetworkExtension itself to
                // send data through the tunnel we have to proxy DNS requests through Apple APIs
                // (and so our actual upstream DNS won't be set in our resolvers, which is why the
                // vanilla WouldLoop won't work for us).  However when active the mac also only
                // queries the main tunnel IP for DNS, so we consider anything else to be
                // upstream-bound DNS to let it through the tunnel.
                return to.getIP() != m_OurIP;
            }
            else if (auto maybe_addr = m_Config.query_bind)
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
        TunEndpoint* const m_Endpoint;
        std::optional<SockAddr> m_QueryBind;
        net::ipaddr_t m_OurIP;

       public:
        std::shared_ptr<dns::PacketSource_Base> PacketSource;

        virtual ~TunDNS() = default;

        explicit TunDNS(TunEndpoint* ep, const llarp::DnsConfig& conf)
            : dns::Server{ep->router().loop(), conf, 0},
              m_Endpoint{ep},
              m_QueryBind{conf.query_bind},
              m_OurIP{ToNet(ep->GetIfAddr())}
        {}

        std::shared_ptr<dns::PacketSource_Base> MakePacketSourceOn(
            const SockAddr&, const llarp::DnsConfig& conf) override
        {
            auto ptr = std::make_shared<DnsInterceptor>(
                [ep = m_Endpoint](auto pkt) {
                    ep->handle_write_ip_packet(pkt.ConstBuffer(), pkt.srcv6(), pkt.dstv6(), 0);
                },
                m_OurIP,
                conf);
            PacketSource = ptr;
            return ptr;
        }
    };

    TunEndpoint::TunEndpoint(Router& r) : BaseHandler{r}, _packet_router{}
    {
        _packet_router =
            std::make_shared<vpn::PacketRouter>([this](net::IPPacket pkt) { handle_user_packet(std::move(pkt)); });

        // r->loop()->add_ticker([this] { Pump(Now()); });
    }

    void TunEndpoint::SetupDNS()
    {
        const auto& info = GetVPNInterface()->Info();
        if (_dns_config.raw)
        {
            auto dns = std::make_shared<TunDNS>(this, _dns_config);
            _dns = dns;

            _packet_router->AddUDPHandler(huint16_t{53}, [this, dns](net::IPPacket pkt) {
                auto dns_pkt_src = dns->PacketSource;
                if (const auto& reply = pkt.reply)
                    dns_pkt_src = std::make_shared<dns::PacketSource_Wrapper>(dns_pkt_src, reply);
                if (dns->MaybeHandlePacket(std::move(dns_pkt_src), pkt.dst(), pkt.src(), *pkt.L4OwnedBuffer()))
                    return;

                handle_user_packet(std::move(pkt));
            });
        }
        else
            _dns = std::make_shared<dns::Server>(router().loop(), _dns_config, info.index);

        _dns->AddResolver(weak_from_this());
        _dns->Start();

        if (_dns_config.raw)
        {
            if (auto vpn = router().vpn_platform())
            {
                // get the first local address we know of
                std::optional<SockAddr> localaddr;
                for (auto res : _dns->GetAllResolvers())
                {
                    if (auto ptr = res.lock())
                    {
                        localaddr = ptr->GetLocalAddr();
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
            }

            if (_raw_DNS)
                _raw_DNS->Start();
        }
    }

    StatusObject TunEndpoint::ExtractStatus() const
    {
        // auto obj = service::Endpoint::ExtractStatus();
        // obj["ifaddr"] = m_OurRange.ToString();
        // obj["ifname"] = m_IfName;

        // std::vector<std::string> upstreamRes;
        // for (const auto& ent : m_DnsConfig.upstream_dns)
        //   upstreamRes.emplace_back(ent.ToString());
        // obj["ustreamResolvers"] = upstreamRes;

        // std::vector<std::string> localRes;
        // for (const auto& ent : m_DnsConfig.bind_addr)
        //   localRes.emplace_back(ent.ToString());
        // obj["localResolvers"] = localRes;

        // // for backwards compat
        // if (not m_DnsConfig.bind_addr.empty())
        //   obj["localResolver"] = localRes[0];

        // StatusObject ips{};
        // for (const auto& item : m_IPActivity)
        // {
        //   StatusObject ipObj{{"lastActive", to_json(item.second)}};
        //   std::string remoteStr;
        //   AlignedBuffer<32> addr = m_IPToAddr.at(item.first);
        //   if (m_SNodes.at(addr))
        //     remoteStr = RouterID(addr.as_array()).ToString();
        //   else
        //     remoteStr = service::Address(addr.as_array()).ToString();
        //   ipObj["remote"] = remoteStr;
        //   std::string ipaddr = item.first.ToString();
        //   ips[ipaddr] = ipObj;
        // }
        // obj["addrs"] = ips;
        // obj["ourIP"] = m_OurIP.ToString();
        // obj["nextIP"] = m_NextIP.ToString();
        // obj["maxIP"] = m_MaxIP.ToString();
        // return obj;
        return {};
    }

    void TunEndpoint::ReconfigureDNS(std::vector<SockAddr> servers)
    {
        if (_dns)
        {
            for (auto weak : _dns->GetAllResolvers())
            {
                if (auto ptr = weak.lock())
                    ptr->ResetResolver(servers);
            }
        }
    }

    bool TunEndpoint::configure(const NetworkConfig& conf, const DnsConfig& dnsConf)
    {
        // if (conf.is_reachable)
        // {
        //   _publish_introset = true;
        //   log::info(logcat, "TunEndpoint setting to be reachable by default");
        // }
        // else
        // {
        //   _publish_introset = false;
        //   log::info(logcat, "TunEndpoint setting to be not reachable by default");
        // }

        if (conf.auth_type == auth::AuthType::FILE)
        {
            // _auth_policy = auth::make_auth_policy<auth::FileAuthPolicy>(router(),
            // conf.auth_files, conf.auth_file_type);
        }
        else if (conf.auth_type != auth::AuthType::NONE)
        {
            std::string url, method;
            if (conf.auth_url.has_value() and conf.auth_method.has_value())
            {
                url = *conf.auth_url;
                method = *conf.auth_method;
            }
            // TODO:
            // auto auth = auth::make_auth_policy<auth::RPCAuthPolicy>(
            //     router(),
            //     url,
            //     method,
            //     conf.auth_whitelist,
            //     conf.auth_static_tokens,
            //     router().lmq(),
            //     shared_from_this());
            // auth->Start();
            // _auth_policy = std::move(auth);
        }

        _dns_config = dnsConf;
        _traffic_policy = conf.traffic_policy;
        _owned_ranges = conf.owned_ranges;

        _base_address_v6 = conf.base_ipv6_addr;

        if (conf.path_alignment_timeout)
        {
            _path_alignment_timeout = *conf.path_alignment_timeout;
        }
        else
            _path_alignment_timeout = service::DEFAULT_PATH_ALIGN_TIMEOUT;

        for (const auto& item : conf.map_addrs)
        {
            if (not MapAddress(item.second, item.first, false))
                return false;
        }

        _if_name = conf.if_name;
        if (_if_name.empty())
        {
            const auto maybe = router().net().FindFreeTun();
            if (not maybe.has_value())
                throw std::runtime_error("cannot find free interface name");
            _if_name = *maybe;
        }

        _local_range = conf.if_addr;
        if (!_local_range.addr.h)
        {
            const auto maybe = router().net().FindFreeRange();
            if (not maybe.has_value())
            {
                throw std::runtime_error("cannot find free address range");
            }
            _local_range = *maybe;
        }

        _local_ip = _local_range.addr;
        _use_v6 = false;

        _persisting_addr_file = conf.addr_map_persist_file;
        if (_persisting_addr_file)
        {
            const auto& file = *_persisting_addr_file;
            if (fs::exists(file))
            {
                bool shouldLoadFile = true;
                {
                    constexpr auto LastModifiedWindow = 1min;
                    const auto lastmodified = fs::last_write_time(file);
                    const auto now = decltype(lastmodified)::clock::now();
                    if (now < lastmodified or now - lastmodified > LastModifiedWindow)
                    {
                        shouldLoadFile = false;
                    }
                }
                std::vector<char> data;
                if (auto maybe = util::OpenFileStream<fs::ifstream>(file, std::ios_base::binary);
                    maybe and shouldLoadFile)
                {
                    LogInfo(name(), " loading address map file from ", file);
                    maybe->seekg(0, std::ios_base::end);
                    const size_t len = maybe->tellg();
                    maybe->seekg(0, std::ios_base::beg);
                    data.resize(len);
                    LogInfo(name(), " reading ", len, " bytes");
                    maybe->read(data.data(), data.size());
                }
                else
                {
                    if (shouldLoadFile)
                    {
                        LogInfo(name(), " address map file ", file, " does not exist, so we won't load it");
                    }
                    else
                        LogInfo(name(), " address map file ", file, " not loaded because it's stale");
                }
                if (not data.empty())
                {
                    std::string_view bdata{data.data(), data.size()};

                    LogDebug(name(), " parsing address map data: ", bdata);

                    const auto parsed = oxenc::bt_deserialize<oxenc::bt_dict>(bdata);

                    for (const auto& [key, value] : parsed)
                    {
                        huint128_t ip{};
                        if (not ip.FromString(key))
                        {
                            LogWarn(name(), " malformed IP in addr map data: ", key);
                            continue;
                        }
                        if (_local_ip == ip)
                            continue;
                        if (not _local_range.Contains(ip))
                        {
                            LogWarn(name(), " out of range IP in addr map data: ", ip);
                            continue;
                        }
                        AddressVariant_t addr;

                        if (const auto* str = std::get_if<std::string>(&value))
                        {
                            if (auto maybe = parse_address(*str))
                            {
                                addr = *maybe;
                            }
                            else
                            {
                                LogWarn(name(), " invalid address in addr map: ", *str);
                                continue;
                            }
                        }
                        else
                        {
                            LogWarn(name(), " invalid first entry in addr map, not a string");
                            continue;
                        }
                        if (const auto* loki = std::get_if<service::Address>(&addr))
                        {
                            m_IPToAddr.emplace(ip, loki->data());
                            m_AddrToIP.emplace(loki->data(), ip);
                            m_SNodes[*loki] = false;
                            LogInfo(name(), " remapped ", ip, " to ", *loki);
                        }
                        if (const auto* snode = std::get_if<RouterID>(&addr))
                        {
                            m_IPToAddr.emplace(ip, snode->data());
                            m_AddrToIP.emplace(snode->data(), ip);
                            m_SNodes[*snode] = true;
                            LogInfo(name(), " remapped ", ip, " to ", *snode);
                        }
                        if (_next_ip < ip)
                            _next_ip = ip;
                        // make sure we dont unmap this guy
                        MarkIPActive(ip);
                    }
                }
            }
            else
            {
                LogInfo(name(), " skipping loading addr map at ", file, " as it does not currently exist");
            }
        }

        // if (auto* quic = GetQUICTunnel())
        // {
        // TODO:
        // quic->listen([this](std::string_view, uint16_t port) {
        //   return llarp::SockAddr{net::TruncateV6(GetIfAddr()), huint16_t{port}};
        // });
        // }
        return true;
    }

    bool TunEndpoint::HasLocalIP(const huint128_t& ip) const
    {
        return m_IPToAddr.find(ip) != m_IPToAddr.end();
    }

    static bool is_random_snode(const dns::Message& msg)
    {
        return msg.questions[0].IsName("random.snode");
    }

    static bool is_localhost_loki(const dns::Message& msg)
    {
        return msg.questions[0].IsLocalhost();
    }

    static dns::Message& clear_dns_message(dns::Message& msg)
    {
        msg.authorities.resize(0);
        msg.additional.resize(0);
        msg.answers.resize(0);
        msg.hdr_fields &= ~dns::flags_RCODENameError;
        return msg;
    }

    std::optional<std::variant<service::Address, RouterID>> TunEndpoint::ObtainAddrForIP(huint128_t ip) const
    {
        auto itr = m_IPToAddr.find(ip);
        if (itr == m_IPToAddr.end())
            return std::nullopt;
        if (m_SNodes.at(itr->second))
            return RouterID{itr->second.as_array()};
        else
            return service::Address{itr->second.as_array()};
    }

    bool TunEndpoint::HandleHookedDNSMessage(dns::Message msg, std::function<void(dns::Message)> reply)
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
        //           [[maybe_unused]] service::SessionTag tag) {
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
        //   llarp::LogWarn("bad number of dns questions: ", msg.questions.size());
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
        //       msg.AddTXTReply(fmt::format("netid={};", RouterContact::ACTIVE_NETID));
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
        //       msg.AddCNAMEReply(random->ToString(), 1);
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
        //           [&msg](const auto&, const auto& exit) { msg.AddCNAMEReply(exit.ToString(), 1);
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
        //           msg.AddCNAMEReply(addr.ToString(), 1);
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
        //       msg.AddCNAMEReply(random->ToString(), 1);
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
        //               [&msg](const auto&, const auto& exit) { msg.AddCNAMEReply(exit.ToString());
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
        //       var::visit([&msg](auto&& result) { msg.AddAReply(result.ToString()); }, *maybe);
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

    bool TunEndpoint::SupportsV6() const
    {
        return _use_v6;
    }

    // FIXME: pass in which question it should be addressing
    bool TunEndpoint::ShouldHookDNSMessage(const dns::Message& msg) const
    {
        llarp::service::Address addr;
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
                    return _local_range.Contains(*ip);
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

    bool TunEndpoint::MapAddress(const service::Address& addr, huint128_t ip, bool SNode)
    {
        auto itr = m_IPToAddr.find(ip);
        if (itr != m_IPToAddr.end())
        {
            llarp::LogWarn(ip, " already mapped to ", service::Address(itr->second.as_array()).ToString());
            return false;
        }
        llarp::LogInfo(name() + " map ", addr.ToString(), " to ", ip);

        m_IPToAddr[ip] = addr;
        m_AddrToIP[addr] = ip;
        m_SNodes[addr] = SNode;
        MarkIPActiveForever(ip);
        // MarkAddressOutbound(addr);
        return true;
    }

    std::string TunEndpoint::GetIfName() const
    {
#ifdef _WIN32
        return net::TruncateV6(GetIfAddr()).ToString();
#else
        return _if_name;
#endif
    }

    bool TunEndpoint::Start()
    {
        return SetupNetworking();
    }

    bool TunEndpoint::IsSNode() const
    {
        // TODO : implement me
        return false;
    }

    bool TunEndpoint::SetupTun()
    {
        _next_ip = _local_ip;
        _max_ip = _local_range.HighestAddr();
        llarp::LogInfo(name(), " set ", _if_name, " to have address ", _local_ip);
        llarp::LogInfo(name(), " allocated up to ", _max_ip, " on range ", _local_range);

        const service::Address ourAddr = _identity.pub.Addr();

        if (not MapAddress(ourAddr, GetIfAddr(), false))
        {
            return false;
        }

        vpn::InterfaceInfo info;
        info.addrs.emplace_back(_local_range);

        if (_base_address_v6)
        {
            IPRange v6range = _local_range;
            v6range.addr = (*_base_address_v6) | _local_range.addr;
            LogInfo(name(), " using v6 range: ", v6range);
            info.addrs.emplace_back(v6range, AF_INET6);
        }

        info.ifname = _if_name;

        LogInfo(name(), " setting up network...");

        try
        {
            _net_if = router().vpn_platform()->CreateInterface(std::move(info), &_router);
        }
        catch (std::exception& ex)
        {
            LogError(name(), " failed to set up network interface: ", ex.what());
            return false;
        }

        _if_name = _net_if->Info().ifname;
        LogInfo(name(), " got network interface ", _if_name);

        auto handle_packet = [netif = _net_if, pktrouter = _packet_router](auto pkt) {
            pkt.reply = [netif](auto pkt) { netif->WritePacket(std::move(pkt)); };
            pktrouter->HandleIPPacket(std::move(pkt));
        };

        if (not router().loop()->add_network_interface(_net_if, std::move(handle_packet)))
        {
            LogError(name(), " failed to add network interface");
            return false;
        }

        _local_ipv6 =
            llarp::huint128_t{llarp::uint128_t{0xfd2e'6c6f'6b69'0000, llarp::net::TruncateV6(_local_range.addr).h}};

        if constexpr (not llarp::platform::is_apple)
        {
            if (auto maybe = router().net().GetInterfaceIPv6Address(_if_name))
            {
                _local_ipv6 = *maybe;
                LogInfo(name(), " has ipv6 address ", _local_ipv6);
            }
        }

        LogInfo(name(), " setting up dns...");
        SetupDNS();
        // loop()->call_soon([this]() { router().route_poker()->set_dns_mode(false); });
        return HasAddress(ourAddr);
    }

    // std::unordered_map<std::string, std::string>
    // TunEndpoint::NotifyParams() const
    // {
    //   auto env = Endpoint::NotifyParams();
    //   env.emplace("IP_ADDR", m_OurIP.ToString());
    //   env.emplace("IF_ADDR", m_OurRange.ToString());
    //   env.emplace("IF_NAME", m_IfName);
    //   std::string strictConnect;
    //   for (const auto& addr : m_StrictConnectAddrs)
    //     strictConnect += addr.ToString() + " ";
    //   env.emplace("STRICT_CONNECT_ADDRS", strictConnect);
    //   return env;
    // }

    bool TunEndpoint::SetupNetworking()
    {
        llarp::LogInfo("Set Up networking for ", name());
        return SetupTun();
    }

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
            LogInfo(name(), " saving address map to ", file);
            // if (auto maybe = util::OpenFileStream<fs::ofstream>(file, std::ios_base::binary))
            // {
            //   std::map<std::string, std::string> addrmap;
            //   for (const auto& [ip, addr] : m_IPToAddr)
            //   {
            //     if (not m_SNodes.at(addr))
            //     {
            //       const service::Address a{addr.as_array()};
            //       if (HasInboundConvo(a))
            //         addrmap[ip.ToString()] = a.ToString();
            //     }
            //   }
            //   const auto data = oxenc::bt_serialize(addrmap);
            //   maybe->write(data.data(), data.size());
            // }
        }
        if (_dns)
            _dns->Stop();
        return true;
        // return llarp::service::Endpoint::Stop();
    }

    std::optional<service::Address> TunEndpoint::ObtainExitAddressFor(
        huint128_t ip, std::function<service::Address(std::unordered_set<service::Address>)> exitSelectionStrat)
    {
        // is it already mapped? return the mapping
        if (auto itr = m_ExitIPToExitAddress.find(ip); itr != m_ExitIPToExitAddress.end())
            return itr->second;

        // const auto& net = router().net();
        // const bool is_bogon = net.IsBogonIP(ip);
        // build up our candidates to choose

        std::unordered_set<service::Address> candidates;
        // for (const auto& entry : _exit_map.FindAllEntries(ip))
        // {
        //   // in the event the exit's range is a bogon range, make sure the ip is located in that
        //   range
        //   // to allow it
        //   if ((is_bogon and net.IsBogonRange(entry.first) and entry.first.Contains(ip))
        //       or entry.first.Contains(ip))
        //     candidates.emplace(entry.second);
        // }
        // // no candidates? bail.
        // if (candidates.empty())
        //   return std::nullopt;
        // if (not exitSelectionStrat)
        // {
        //   // default strat to random choice
        //   exitSelectionStrat = [](auto candidates) {
        //     auto itr = candidates.begin();
        //     std::advance(itr, llarp::randint() % candidates.size());
        //     return *itr;
        //   };
        // }
        // map the exit and return the endpoint we mapped it to
        return m_ExitIPToExitAddress.emplace(ip, exitSelectionStrat(candidates)).first->second;
    }

    void TunEndpoint::handle_user_packet(net::IPPacket pkt)
    {
        huint128_t dst, src;
        if (pkt.IsV4())
        {
            dst = pkt.dst4to6();
            src = pkt.src4to6();
        }
        else
        {
            dst = pkt.dstv6();
            src = pkt.srcv6();
        }

        if constexpr (llarp::platform::is_apple)
        {
            if (dst == _local_ip)
            {
                handle_write_ip_packet(pkt.ConstBuffer(), src, dst, 0);
                return;
            }
        }

        // if (_state->is_exit_enabled)
        // {
        //   dst = net::ExpandV4(net::TruncateV6(dst));
        // }

        auto itr = m_IPToAddr.find(dst);

        if (itr == m_IPToAddr.end())
        {
            service::Address addr{};

            if (auto maybe = ObtainExitAddressFor(dst))
                addr = *maybe;
            else
            {
                // send icmp unreachable as we dont have any exits for this ip
                if (const auto icmp = pkt.MakeICMPUnreachable())
                    handle_write_ip_packet(icmp->ConstBuffer(), dst, src, 0);

                return;
            }

            std::function<void(void)> extra_cb;

            // if (not HasFlowToService(addr))
            // {
            //   extra_cb = [poker = router().route_poker()]() { poker->put_up(); };
            // }

            // pkt.ZeroSourceAddress();
            // MarkAddressOutbound(addr);

            // EnsurePathToService(
            //     addr,
            //     [pkt, extra_cb, this](service::Address addr, service::OutboundContext* ctx)
            //     mutable {
            //       if (ctx)
            //       {
            //         if (extra_cb)
            //           extra_cb();
            //         ctx->send_packet_to_remote(pkt.to_string());
            //         router().TriggerPump();
            //         return;
            //       }
            //       LogWarn("cannot ensure path to exit ", addr, " so we drop some packets");
            //     },
            //     PathAlignmentTimeout());
            return;
        }
        std::variant<service::Address, RouterID> to;
        service::ProtocolType type{};
        // if (m_SNodes.at(itr->second))
        // {
        //   to = RouterID{itr->second.as_array()};
        //   type = service::ProtocolType::TrafficV4;
        // }
        // else
        // {
        //   to = service::Address{itr->second.as_array()};
        //   type = _state->is_exit_enabled and src != m_OurIP ? service::ProtocolType::Exit
        //                                                     : pkt.ServiceProtocol();
        // }

        // prepare packet for insertion into network
        // this includes clearing IP addresses, recalculating checksums, etc
        // this does not happen for exits because the point is they don't rewrite addresses
        // TODO: can we fix this shit
        //  - clear addresses if it is our local TUN address, invariant of protocoltype
        if (type != service::ProtocolType::Exit)
        {
            if (pkt.IsV4())
                pkt.UpdateIPv4Address({0}, {0});
            else
                pkt.UpdateIPv6Address({0}, {0});
        }
        // try sending it on an existing convotag
        // this succeds for inbound convos, probably.
        // if (auto maybe = GetBestConvoTagFor(to))
        // {
        //   if (send_to(*maybe, pkt.to_string()))
        //   {
        //     MarkIPActive(dst);
        //     router().TriggerPump();
        //     return;
        //   }
        // }
        // // try establishing a path to this guy
        // // will fail if it's an inbound convo
        // EnsurePathTo(
        //     to,
        //     [pkt, dst, to, this](auto maybe) mutable {
        //       if (not maybe)
        //       {
        //         var::visit(
        //             [this](auto&& addr) {
        //               LogWarn(name(), " failed to ensure path to ", addr, " no convo tag found");
        //             },
        //             to);
        //       }
        //       if (send_to(*maybe, pkt.to_string()))
        //       {
        //         MarkIPActive(dst);
        //         router().TriggerPump();
        //       }
        //       else
        //       {
        //         var::visit(
        //             [this](auto&& addr) {
        //               LogWarn(name(), " failed to send to ", addr, ", SendToOrQueue failed");
        //             },
        //             to);
        //       }
        //     },
        //     PathAlignmentTimeout());
    }

    bool TunEndpoint::ShouldAllowTraffic(const net::IPPacket& pkt) const
    {
        if (const auto exitPolicy = GetExitPolicy())
        {
            if (not exitPolicy->AllowsTraffic(pkt))
                return false;
        }

        return true;
    }

    bool TunEndpoint::HandleInboundPacket(
        const service::SessionTag tag, const llarp_buffer_t& buf, service::ProtocolType t, uint64_t seqno)
    {
        LogTrace("Inbound ", t, " packet (", buf.sz, "B) on convo ", tag);

        // if (t == service::ProtocolType::QUIC)
        // {
        //   auto* quic = GetQUICTunnel();
        //   if (!quic)
        //   {
        //     LogWarn("incoming quic packet but this endpoint is not quic capable; dropping");
        //     return false;
        //   }
        //   if (buf.sz < 4)
        //   {
        //     LogWarn("invalid incoming quic packet, dropping");
        //     return false;
        //   }
        //   LogInfo("tag active T=", tag);

        //   // TODO:
        //   // quic->receive_packet(tag, buf);
        //   return true;
        // }

        if (t != service::ProtocolType::TrafficV4 && t != service::ProtocolType::TrafficV6
            && t != service::ProtocolType::Exit)
            return false;
        std::variant<service::Address, RouterID> addr;
        // if (auto maybe = GetEndpointWithConvoTag(tag))
        // {
        //   addr = *maybe;
        // }
        // else
        //   return false;
        huint128_t src, dst;

        net::IPPacket pkt;
        if (not pkt.Load(buf))
            return false;

        // if (_state->is_exit_enabled)
        // {
        //   // exit side from exit

        //   // check packet against exit policy and if as needed
        //   if (not ShouldAllowTraffic(pkt))
        //     return false;

        //   src = ObtainIPForAddr(addr);
        //   if (t == service::ProtocolType::Exit)
        //   {
        //     if (pkt.IsV4())
        //       dst = pkt.dst4to6();
        //     else if (pkt.IsV6())
        //     {
        //       dst = pkt.dstv6();
        //       src = net::ExpandV4Lan(net::TruncateV6(src));
        //     }
        //   }
        //   else
        //   {
        //     // non exit traffic on exit
        //     dst = m_OurIP;
        //   }
        // }
        // else if (t == service::ProtocolType::Exit)
        // {
        //   // client side exit traffic from exit
        //   if (pkt.IsV4())
        //   {
        //     dst = m_OurIP;
        //     src = pkt.src4to6();
        //   }
        //   else if (pkt.IsV6())
        //   {
        //     dst = m_OurIPv6;
        //     src = pkt.srcv6();
        //   }
        //   // find what exit we think this should be for
        //   service::Address fromAddr{};
        //   if (const auto* ptr = std::get_if<service::Address>(&addr))
        //   {
        //     fromAddr = *ptr;
        //   }
        //   else  // don't allow snode
        //     return false;
        //   // make sure the mapping matches
        //   if (auto itr = m_ExitIPToExitAddress.find(src); itr != m_ExitIPToExitAddress.end())
        //   {
        //     if (itr->second != fromAddr)
        //       return false;
        //   }
        //   else
        //     return false;
        // }
        // else
        // {
        //   // snapp traffic
        //   src = ObtainIPForAddr(addr);
        //   dst = m_OurIP;
        // }
        handle_write_ip_packet(buf, src, dst, seqno);
        return true;
    }

    bool TunEndpoint::handle_write_ip_packet(const llarp_buffer_t& b, huint128_t src, huint128_t dst, uint64_t seqno)
    {
        ManagedBuffer buf(b);
        WritePacket write;
        write.seqno = seqno;
        auto& pkt = write.pkt;
        // load
        if (!pkt.Load(buf))
        {
            return false;
        }
        if (pkt.IsV4())
        {
            pkt.UpdateIPv4Address(xhtonl(net::TruncateV6(src)), xhtonl(net::TruncateV6(dst)));
        }
        else if (pkt.IsV6())
        {
            pkt.UpdateIPv6Address(src, dst);
        }

        // TODO: send this along but without a fucking huint182_t
        // m_NetworkToUserPktQueue.push(std::move(write));

        // wake up so we ensure that all packets are written to user
        // router().TriggerPump();
        return true;
    }

    huint128_t TunEndpoint::GetIfAddr() const
    {
        return _local_ip;
    }

    huint128_t TunEndpoint::ObtainIPForAddr(std::variant<service::Address, RouterID> addr)
    {
        llarp_time_t now = llarp::time_now_ms();
        huint128_t nextIP = {0};
        AlignedBuffer<32> ident{};
        bool snode = false;

        var::visit([&ident](auto&& val) { ident = val.data(); }, addr);

        if (std::get_if<RouterID>(&addr))
        {
            snode = true;
        }

        {
            // previously allocated address
            auto itr = m_AddrToIP.find(ident);
            if (itr != m_AddrToIP.end())
            {
                // mark ip active
                MarkIPActive(itr->second);
                return itr->second;
            }
        }
        // allocate new address
        if (_next_ip < _max_ip)
        {
            do
            {
                nextIP = ++_next_ip;
            } while (m_IPToAddr.find(nextIP) != m_IPToAddr.end() && _next_ip < _max_ip);
            if (nextIP < _max_ip)
            {
                m_AddrToIP[ident] = nextIP;
                m_IPToAddr[nextIP] = ident;
                m_SNodes[ident] = snode;
                var::visit([&](auto&& remote) { llarp::LogInfo(name(), " mapped ", remote, " to ", nextIP); }, addr);
                MarkIPActive(nextIP);
                return nextIP;
            }
        }

        // we are full
        // expire least active ip
        // TODO: prevent DoS
        std::pair<huint128_t, llarp_time_t> oldest = {huint128_t{0}, 0s};

        // find oldest entry
        auto itr = _ip_activity.begin();
        while (itr != _ip_activity.end())
        {
            if (itr->second <= now)
            {
                if ((now - itr->second) > oldest.second)
                {
                    oldest.first = itr->first;
                    oldest.second = itr->second;
                }
            }
            ++itr;
        }
        // remap address
        m_IPToAddr[oldest.first] = ident;
        m_AddrToIP[ident] = oldest.first;
        m_SNodes[ident] = snode;
        nextIP = oldest.first;

        // mark ip active
        _ip_activity[nextIP] = std::max(_ip_activity[nextIP], now);

        return nextIP;
    }

    bool TunEndpoint::HasRemoteForIP(huint128_t ip) const
    {
        return m_IPToAddr.find(ip) != m_IPToAddr.end();
    }

    void TunEndpoint::MarkIPActive(huint128_t ip)
    {
        llarp::LogDebug(name(), " address ", ip, " is active");
        _ip_activity[ip] = std::max(llarp::time_now_ms(), _ip_activity[ip]);
    }

    void TunEndpoint::MarkIPActiveForever(huint128_t ip)
    {
        _ip_activity[ip] = std::numeric_limits<llarp_time_t>::max();
    }

    TunEndpoint::~TunEndpoint() = default;

}  // namespace llarp::handlers
