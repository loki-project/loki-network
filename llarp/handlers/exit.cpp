#include "exit.hpp"

#include <llarp/dns/dns.hpp>
#include <llarp/net/net.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path_context.hpp>
#include <llarp/router/router.hpp>
#include <llarp/service/protocol_type.hpp>

#include <cassert>

namespace llarp::handlers
{
    ExitEndpoint::ExitEndpoint(std::string name, Router* r) : router(r), name(std::move(name))
    // , tunnel_manager{std::make_shared<link::TunnelManager>(*this)}
    {
        should_init_tun = true;
    }

    ExitEndpoint::~ExitEndpoint() = default;

    void ExitEndpoint::lookup_name(std::string, std::function<void(std::string, bool)>)
    {
        // TODO: implement me (or does EndpointBase having this method as virtual even make sense?)
    }

    void ExitEndpoint::LookupServiceAsync(
        std::string, std::string, std::function<void(std::vector<dns::SRVData>)> resultHandler)
    {
        // TODO: implement me
        resultHandler({});
    }

    std::optional<EndpointBase::AddressVariant_t> ExitEndpoint::GetEndpointWithConvoTag(service::ConvoTag tag) const
    {
        for (const auto& [pathID, pk] : paths)
        {
            if (pathID.as_array() == tag.as_array())
                return RouterID{pk.as_array()};
        }
        for (const auto& [rid, session] : snode_sessions)
        {
            PathID_t pathID{tag.as_array()};
            if (session->GetPathByID(pathID))
                return rid;
        }
        return std::nullopt;
    }

    std::optional<service::ConvoTag> ExitEndpoint::GetBestConvoTagFor(AddressVariant_t addr) const
    {
        if (auto* rid = std::get_if<RouterID>(&addr))
        {
            service::ConvoTag tag{};
            auto visit = [&tag](exit::Endpoint* const ep) -> bool {
                if (not ep)
                    return false;
                if (auto path = ep->GetCurrentPath())
                    tag = service::ConvoTag{path->RXID().as_array()};
                return true;
            };
            if (VisitEndpointsFor(PubKey{*rid}, visit) and not tag.IsZero())
                return tag;
            auto itr = snode_sessions.find(*rid);
            if (itr == snode_sessions.end())
            {
                return std::nullopt;
            }
            if (auto path = itr->second->GetPathByRouter(*rid))
            {
                tag = service::ConvoTag{path->RXID().as_array()};
                return tag;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    const EventLoop_ptr& ExitEndpoint::Loop()
    {
        return router->loop();
    }

    bool ExitEndpoint::send_to(service::ConvoTag tag, std::string payload)
    {
        if (auto maybeAddr = GetEndpointWithConvoTag(tag))
        {
            if (std::holds_alternative<service::Address>(*maybeAddr))
                return false;
            if (auto* rid = std::get_if<RouterID>(&*maybeAddr))
            {
                for (auto [itr, end] = active_exits.equal_range(PubKey{*rid}); itr != end; ++itr)
                {
                    if (not itr->second->LooksDead(Now()))
                    {
                        return router->send_data_message(itr->second->router_id(), std::move(payload));
                    }
                }

                if (not router->PathToRouterAllowed(*rid))
                    return false;

                ObtainSNodeSession(
                    *rid, [pkt = std::move(payload)](std::shared_ptr<llarp::exit::BaseSession> session) mutable {
                        if (session and session->IsReady())
                        {
                            session->send_packet_to_remote(std::move(pkt));
                        }
                    });
            }
            return true;
        }
        return false;
    }

    bool ExitEndpoint::EnsurePathTo(
        AddressVariant_t addr, std::function<void(std::optional<service::ConvoTag>)> hook, llarp_time_t)
    {
        if (std::holds_alternative<service::Address>(addr))
            return false;
        if (auto* rid = std::get_if<RouterID>(&addr))
        {
            if (snode_keys.count(PubKey{*rid}) or router->PathToRouterAllowed(*rid))
            {
                ObtainSNodeSession(*rid, [hook, routerID = *rid](std::shared_ptr<exit::BaseSession> session) {
                    if (session and session->IsReady())
                    {
                        if (auto path = session->GetPathByRouter(routerID))
                        {
                            hook(service::ConvoTag{path->RXID().as_array()});
                        }
                        else
                            hook(std::nullopt);
                    }
                    else
                        hook(std::nullopt);
                });
            }
            else
            {
                // probably a client
                hook(GetBestConvoTagFor(addr));
            }
        }
        return true;
    }

    util::StatusObject ExitEndpoint::ExtractStatus() const
    {
        util::StatusObject obj{{"permitExit", permit_exit}, {"ip", if_addr.to_string()}};
        util::StatusObject exitsObj{};
        for (const auto& item : active_exits)
        {
            exitsObj[item.first.to_string()] = item.second->ExtractStatus();
        }
        obj["exits"] = exitsObj;
        return obj;
    }

    bool ExitEndpoint::SupportsV6() const
    {
        return use_ipv6;
    }

    bool ExitEndpoint::ShouldHookDNSMessage(const dns::Message& msg) const
    {
        if (msg.questions.size() == 0)
            return false;
        // always hook ptr for ranges we own
        if (msg.questions[0].qtype == dns::qTypePTR)
        {
            if (auto ip = dns::DecodePTR(msg.questions[0].qname))
                return ip_range.Contains(*ip);
            return false;
        }
        if (msg.questions[0].qtype == dns::qTypeA || msg.questions[0].qtype == dns::qTypeCNAME
            || msg.questions[0].qtype == dns::qTypeAAAA)
        {
            if (msg.questions[0].IsName("localhost.loki"))
                return true;
            if (msg.questions[0].HasTLD(".snode"))
                return true;
        }
        return false;
    }

    bool ExitEndpoint::MaybeHookDNS(
        std::shared_ptr<dns::PacketSource_Base> source,
        const dns::Message& query,
        const SockAddr& to,
        const SockAddr& from)
    {
        if (not ShouldHookDNSMessage(query))
            return false;

        auto job = std::make_shared<dns::QueryJob>(source, query, to, from);
        if (not HandleHookedDNSMessage(query, [job](auto msg) { job->SendReply(msg.ToBuffer()); }))
            job->Cancel();
        return true;
    }

    bool ExitEndpoint::HandleHookedDNSMessage(dns::Message msg, std::function<void(dns::Message)> reply)
    {
        if (msg.questions[0].qtype == dns::qTypePTR)
        {
            auto ip = dns::DecodePTR(msg.questions[0].qname);
            if (not ip)
                return false;
            if (ip == if_addr)
            {
                RouterID us = GetRouter()->pubkey();
                msg.AddAReply(us.to_string(), 300);
            }
            else
            {
                auto itr = ip_to_key.find(*ip);
                if (itr != ip_to_key.end() && snode_keys.find(itr->second) != snode_keys.end())
                {
                    RouterID them{itr->second.data()};
                    msg.AddAReply(them.to_string());
                }
                else
                    msg.AddNXReply();
            }
        }
        else if (msg.questions[0].qtype == dns::qTypeCNAME)
        {
            if (msg.questions[0].IsName("random.snode"))
            {
                if (auto random = GetRouter()->GetRandomGoodRouter())
                    msg.AddCNAMEReply(random->to_string(), 1);
                else
                    msg.AddNXReply();
            }
            else if (msg.questions[0].IsName("localhost.loki"))
            {
                RouterID us = router->pubkey();
                msg.AddAReply(us.to_string(), 1);
            }
            else
                msg.AddNXReply();
        }
        else if (msg.questions[0].qtype == dns::qTypeA || msg.questions[0].qtype == dns::qTypeAAAA)
        {
            const bool isV6 = msg.questions[0].qtype == dns::qTypeAAAA;
            const bool isV4 = msg.questions[0].qtype == dns::qTypeA;
            if (msg.questions[0].IsName("random.snode"))
            {
                if (auto random = GetRouter()->GetRandomGoodRouter())
                {
                    msg.AddCNAMEReply(random->to_string(), 1);
                    auto ip = ObtainServiceNodeIP(*random);
                    msg.AddINReply(ip, false);
                }
                else
                    msg.AddNXReply();
                reply(msg);
                return true;
            }
            if (msg.questions[0].IsName("localhost.loki"))
            {
                msg.AddINReply(GetIfAddr(), isV6);
                reply(msg);
                return true;
            }
            // forward dns for snode
            RouterID r;
            if (r.from_string(msg.questions[0].Name()))
            {
                huint128_t ip;
                PubKey pubKey(r);
                if (isV4 && SupportsV6())
                {
                    msg.hdr_fields |= dns::flags_QR | dns::flags_AA | dns::flags_RA;
                }
                else if (snode_keys.find(pubKey) == snode_keys.end())
                {
                    // we do not have it mapped, async obtain it
                    ObtainSNodeSession(
                        r,
                        [&, msg = std::make_shared<dns::Message>(msg), reply](
                            std::shared_ptr<exit::BaseSession> session) {
                            if (session && session->IsReady())
                            {
                                msg->AddINReply(key_to_IP[pubKey], isV6);
                            }
                            else
                            {
                                msg->AddNXReply();
                            }
                            reply(*msg);
                        });
                    return true;
                }
                else
                {
                    // we have it mapped already as a service node
                    auto itr = key_to_IP.find(pubKey);
                    if (itr != key_to_IP.end())
                    {
                        ip = itr->second;
                        msg.AddINReply(ip, isV6);
                    }
                    else  // fallback case that should never happen (probably)
                        msg.AddNXReply();
                }
            }
            else
                msg.AddNXReply();
        }
        reply(msg);
        return true;
    }

    void ExitEndpoint::ObtainSNodeSession(const RouterID& rid, exit::SessionReadyFunc obtain_cb)
    {
        if (not router->node_db()->is_connection_allowed(rid))
        {
            obtain_cb(nullptr);
            return;
        }
        ObtainServiceNodeIP(rid);
        snode_sessions[rid]->AddReadyHook(obtain_cb);
    }

    llarp_time_t ExitEndpoint::Now() const
    {
        return router->now();
    }

    bool ExitEndpoint::VisitEndpointsFor(const PubKey& pk, std::function<bool(exit::Endpoint* const)> visit) const
    {
        for (auto [itr, end] = active_exits.equal_range(pk); itr != end; ++itr)
        {
            if (not visit(itr->second.get()))
                return true;
        }
        return false;
    }

    void ExitEndpoint::Flush()
    {
        while (not inet_to_network.empty())
        {
            auto& top = inet_to_network.top();

            // get a session by public key
            std::optional<PubKey> maybe_pk;
            {
                auto itr = ip_to_key.find(top.dstv6());
                if (itr != ip_to_key.end())
                    maybe_pk = itr->second;
            }

            auto buf = const_cast<net::IPPacket&>(top);
            inet_to_network.pop();
            // we have no session for public key so drop
            if (not maybe_pk)
                continue;  // we are in a while loop

            const auto& pk = *maybe_pk;

            // check if this key is a service node
            if (snode_keys.count(pk))
            {
                // check if it's a service node session we made and queue it via our
                // snode session that we made otherwise use an inbound session that
                // was made by the other service node
                auto itr = snode_sessions.find(RouterID{pk.data()});
                if (itr != snode_sessions.end())
                {
                    itr->second->send_packet_to_remote(buf.to_string());
                    // we are in a while loop
                    continue;
                }
            }
            auto tryFlushingTraffic = [this, buf = std::move(buf), pk](exit::Endpoint* const ep) -> bool {
                if (!ep->QueueInboundTraffic(buf._buf, service::ProtocolType::TrafficV4))
                {
                    LogWarn(Name(), " dropped inbound traffic for session ", pk, " as we are overloaded (probably)");
                    // continue iteration
                    return true;
                }
                // break iteration
                return false;
            };
            if (!VisitEndpointsFor(pk, tryFlushingTraffic))
            {
                // we may have all dead sessions, wtf now?
                LogWarn(Name(), " dropped inbound traffic for session ", pk, " as we have no working endpoints");
            }
        }

        for (auto& [pubkey, endpoint] : active_exits)
        {
            if (!endpoint->Flush())
            {
                LogWarn("exit session with ", pubkey, " dropped packets");
            }
        }
        for (auto& [id, session] : snode_sessions)
        {
            session->FlushUpstream();
            session->FlushDownstream();
        }
    }

    bool ExitEndpoint::Start()
    {
        // map our address
        const PubKey us(router->pubkey());
        const huint128_t ip = GetIfAddr();
        key_to_IP[us] = ip;
        ip_to_key[ip] = us;
        ip_activity[ip] = std::numeric_limits<llarp_time_t>::max();
        snode_keys.insert(us);

        if (should_init_tun)
        {
            vpn::InterfaceInfo info;
            info.ifname = if_name;
            info.addrs.emplace_back(ip_range);

            if_net = GetRouter()->vpn_platform()->CreateInterface(std::move(info), router);
            if (not if_net)
            {
                llarp::LogError("Could not create interface");
                return false;
            }
            if (not GetRouter()->loop()->add_network_interface(
                    if_net, [this](net::IPPacket pkt) { OnInetPacket(std::move(pkt)); }))
            {
                llarp::LogWarn("Could not create tunnel for exit endpoint");
                return false;
            }

            GetRouter()->loop()->add_ticker([this] { Flush(); });
#ifndef _WIN32
            resolver = std::make_shared<dns::Server>(router->loop(), dns_conf, if_nametoindex(if_name.c_str()));
            resolver->Start();

#endif
        }
        return true;
    }

    Router* ExitEndpoint::GetRouter()
    {
        return router;
    }

    huint128_t ExitEndpoint::GetIfAddr() const
    {
        return if_addr;
    }

    bool ExitEndpoint::Stop()
    {
        for (auto& item : snode_sessions)
            item.second->Stop();
        return true;
    }

    bool ExitEndpoint::ShouldRemove() const
    {
        for (auto& item : snode_sessions)
            if (!item.second->ShouldRemove())
                return false;
        return true;
    }

    bool ExitEndpoint::HasLocalMappedAddrFor(const PubKey& pk) const
    {
        return key_to_IP.find(pk) != key_to_IP.end();
    }

    huint128_t ExitEndpoint::GetIPForIdent(const PubKey pk)
    {
        huint128_t found{};
        if (!HasLocalMappedAddrFor(pk))
        {
            // allocate and map
            found = AllocateNewAddress();
            if (!key_to_IP.emplace(pk, found).second)
            {
                LogError(Name(), "failed to map ", pk, " to ", found);
                return found;
            }
            if (!ip_to_key.emplace(found, pk).second)
            {
                LogError(Name(), "failed to map ", found, " to ", pk);
                return found;
            }
            if (HasLocalMappedAddrFor(pk))
                LogInfo(Name(), " mapping ", pk, " to ", found);
            else
                LogError(Name(), "failed to map ", pk, " to ", found);
        }
        else
            found = key_to_IP[pk];

        MarkIPActive(found);
        key_to_IP.rehash(0);
        assert(HasLocalMappedAddrFor(pk));
        return found;
    }

    huint128_t ExitEndpoint::AllocateNewAddress()
    {
        if (next_addr < highest_addr)
            return ++next_addr;

        // find oldest activity ip address
        huint128_t found = {0};
        llarp_time_t min = std::numeric_limits<llarp_time_t>::max();
        for (const auto& [addr, time] : ip_activity)
        {
            if (time < min)
            {
                found.h = addr.h;
                min = time;
            }
        }
        // kick old ident off exit
        // TODO: DoS
        PubKey pk = ip_to_key[found];
        KickIdentOffExit(pk);

        return found;
    }

    EndpointBase::AddressVariant_t ExitEndpoint::LocalAddress() const
    {
        return RouterID{router->pubkey()};
    }

    void ExitEndpoint::SRVRecordsChanged()
    {
        // TODO: Investigate the usage or the term exit RE: service nodes acting as exits
    }

    std::optional<EndpointBase::SendStat> ExitEndpoint::GetStatFor(AddressVariant_t) const
    {
        /// TODO: implement me
        return std::nullopt;
    }

    std::unordered_set<EndpointBase::AddressVariant_t> ExitEndpoint::AllRemoteEndpoints() const
    {
        std::unordered_set<AddressVariant_t> remote;
        for (const auto& [path, pubkey] : paths)
        {
            remote.insert(RouterID{pubkey.data()});
        }
        return remote;
    }

    bool ExitEndpoint::QueueOutboundTraffic(net::IPPacket pkt)
    {
        return if_net && if_net->WritePacket(std::move(pkt));
    }

    void ExitEndpoint::KickIdentOffExit(const PubKey& pk)
    {
        LogInfo(Name(), " kicking ", pk, " off exit");
        huint128_t ip = key_to_IP[pk];
        key_to_IP.erase(pk);
        ip_to_key.erase(ip);
        for (auto [exit_itr, end] = active_exits.equal_range(pk); exit_itr != end;)
            exit_itr = active_exits.erase(exit_itr);
    }

    void ExitEndpoint::MarkIPActive(huint128_t ip)
    {
        ip_activity[ip] = GetRouter()->now();
    }

    void ExitEndpoint::OnInetPacket(net::IPPacket pkt)
    {
        inet_to_network.emplace(std::move(pkt));
    }

    bool ExitEndpoint::QueueSNodePacket(const llarp_buffer_t& buf, huint128_t from)
    {
        net::IPPacket pkt{buf.view_all()};
        if (pkt.empty())
            return false;
        // rewrite ip
        if (use_ipv6)
            pkt.UpdateIPv6Address(from, if_addr);
        else
            pkt.UpdateIPv4Address(xhtonl(net::TruncateV6(from)), xhtonl(net::TruncateV6(if_addr)));
        return if_net and if_net->WritePacket(std::move(pkt));
    }

    exit::Endpoint* ExitEndpoint::FindEndpointByPath(const PathID_t& path)
    {
        exit::Endpoint* endpoint = nullptr;
        PubKey pk;
        if (auto itr = paths.find(path); itr != paths.end())
            pk = itr->second;
        else
            return nullptr;
        if (auto itr = active_exits.find(pk); itr != active_exits.end())
        {
            if (itr->second->PubKey() == pk)
                endpoint = itr->second.get();
        }
        return endpoint;
    }

    bool ExitEndpoint::UpdateEndpointPath(const PubKey& remote, const PathID_t& next)
    {
        // check if already mapped
        if (auto itr = paths.find(next); itr != paths.end())
            return false;
        paths.emplace(next, remote);
        return true;
    }

    void ExitEndpoint::Configure(const NetworkConfig& networkConfig, const DnsConfig& dnsConfig)
    {
        /*
          * TODO: pre-config refactor, this was checking a couple things that were extremely vague
          *       these could have appeared on either [dns] or [network], but they weren't
        documented
          *       anywhere
          *
        if (k == "type" && v == "null")
        {
          m_ShouldInitTun = false;
          return true;
        }
        if (k == "exit")
        {
          m_PermitExit = IsTrueValue(v.c_str());
          return true;
        }
          */

        dns_conf = dnsConfig;

        if (networkConfig.endpoint_type == "null")
        {
            should_init_tun = false;
        }

        ip_range = networkConfig.if_addr;
        if (!ip_range.addr.h)
        {
            const auto maybe = router->net().find_free_range();
            if (not maybe.has_value())
                throw std::runtime_error("cannot find free interface range");
            ip_range = *maybe;
        }
        const auto host_str = ip_range.BaseAddressString();
        // string, or just a plain char array?
        if_addr = ip_range.addr;
        next_addr = if_addr;
        highest_addr = ip_range.HighestAddr();
        use_ipv6 = not ip_range.IsV4();

        if_name = networkConfig.if_name;
        if (if_name.empty())
        {
            const auto maybe = router->net().FindFreeTun();
            if (not maybe.has_value())
                throw std::runtime_error("cannot find free interface name");
            if_name = *maybe;
        }
        LogInfo(Name(), " set ifname to ", if_name);
        // if (auto* quic = GetQUICTunnel())
        // {
        // quic->listen([ifaddr = net::TruncateV6(if_addr)](std::string_view, uint16_t port) {
        //   return llarp::SockAddr{ifaddr, huint16_t{port}};
        // });
        // }
    }

    huint128_t ExitEndpoint::ObtainServiceNodeIP(const RouterID& other)  // "find router"
    {
        const PubKey pubKey{other};
        const PubKey us{router->pubkey()};
        // just in case
        if (pubKey == us)
            return if_addr;

        huint128_t ip = GetIPForIdent(pubKey);
        if (snode_keys.emplace(pubKey).second)
        {
            auto session = std::make_shared<exit::SNodeSession>(
                other,
                [this, ip](const auto& buf) { return QueueSNodePacket(buf, ip); },
                GetRouter(),
                2,
                1,
                true,
                this);
            // this is a new service node make an outbound session to them
            snode_sessions[other] = session;
        }
        return ip;
    }

    link::TunnelManager* ExitEndpoint::GetQUICTunnel()
    {
        return nullptr;
        // return tunnel_manager.get();
    }

    bool ExitEndpoint::AllocateNewExit(const PubKey pk, const PathID_t& path, bool wantInternet)
    {
        if (wantInternet && !permit_exit)
            return false;
        // TODO: is this getting a path or a transit hop or...somehow possibly either?
        // std::shared_ptr<path::AbstractHopHandler> handler =
        // router->path_context().GetByUpstream(router->pubkey(), path);
        std::shared_ptr<path::AbstractHopHandler> handler{};
        if (handler == nullptr)
            return false;
        auto ip = GetIPForIdent(pk);
        if (GetRouter()->path_context().TransitHopPreviousIsRouter(path, pk.as_array()))
        {
            // we think this path belongs to a service node
            // mark it as such so we don't make an outbound session to them
            snode_keys.emplace(pk.as_array());
        }
        active_exits.emplace(pk, std::make_unique<exit::Endpoint>(pk, handler, !wantInternet, ip, this));

        paths[path] = pk;

        return HasLocalMappedAddrFor(pk);
    }

    std::string ExitEndpoint::Name() const
    {
        return name;
    }

    void ExitEndpoint::DelEndpointInfo(const PathID_t& path)
    {
        paths.erase(path);
    }

    void ExitEndpoint::RemoveExit(const exit::Endpoint* ep)
    {
        for (auto [itr, end] = active_exits.equal_range(ep->PubKey()); itr != end; ++itr)
        {
            if (itr->second->GetCurrentPath() == ep->GetCurrentPath())
            {
                active_exits.erase(itr);
                // now ep is gone af
                return;
            }
        }
    }

    void ExitEndpoint::Tick(llarp_time_t now)
    {
        {
            auto itr = snode_sessions.begin();
            while (itr != snode_sessions.end())
            {
                if (itr->second->IsExpired(now))
                    itr = snode_sessions.erase(itr);
                else
                {
                    itr->second->Tick(now);
                    ++itr;
                }
            }
        }
        {
            // expire
            auto itr = active_exits.begin();
            while (itr != active_exits.end())
            {
                if (itr->second->IsExpired(now))
                    itr = active_exits.erase(itr);
                else
                    ++itr;
            }
            // pick chosen exits and tick
            chosen_exits.clear();
            itr = active_exits.begin();
            while (itr != active_exits.end())
            {
                // do we have an exit set for this key?
                if (chosen_exits.find(itr->first) != chosen_exits.end())
                {
                    // yes
                    if (chosen_exits[itr->first]->createdAt < itr->second->createdAt)
                    {
                        // if the iterators's exit is newer use it for the chosen exit for
                        // key
                        if (!itr->second->LooksDead(now))
                            chosen_exits[itr->first] = itr->second.get();
                    }
                }
                else if (!itr->second->LooksDead(now))  // set chosen exit if not dead for key that
                                                        // doesn't have one yet
                    chosen_exits[itr->first] = itr->second.get();
                // tick which clears the tx rx counters
                itr->second->Tick(now);
                ++itr;
            }
        }
    }
}  // namespace llarp::handlers
