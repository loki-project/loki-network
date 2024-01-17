#include "handler.hpp"

#include "types.hpp"

#include <llarp/dns/dns.hpp>
#include <llarp/messages/common.hpp>
#include <llarp/net/net.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path_context.hpp>
#include <llarp/router/router.hpp>

#include <cassert>

namespace llarp::service
{
    Handler::Handler(std::string name, Router& r) : handlers::RemoteHandler{std::move(name), r}
    {}

    Handler::~Handler() = default;

    // bool Handler::EnsurePathTo(
    //     AddressVariant_t addr,
    //     std::function<void(std::optional<service::SessionTag>)> hook,
    //     llarp_time_t)
    // {
    //   if (std::holds_alternative<service::Address>(addr))
    //     return false;
    //   if (auto* rid = std::get_if<RouterID>(&addr))
    //   {
    //     if (snode_keys.count(PubKey{*rid}) or _router.PathToRouterAllowed(*rid))
    //     {
    //       // ObtainSNodeSession(
    //       //     *rid, [hook, routerID = *rid](std::shared_ptr<session::BaseSession> session) {
    //       //       if (session and session->IsReady())
    //       //       {
    //       //         if (auto path = session->GetPathByRouter(routerID))
    //       //         {
    //       //           hook(service::ConvoTag{path->RXID().as_array()});
    //       //         }
    //       //         else
    //       //           hook(std::nullopt);
    //       //       }
    //       //       else
    //       //         hook(std::nullopt);
    //       //     });
    //     }
    //     else
    //     {
    //       // probably a client
    //       hook(GetBestConvoTagFor(addr));
    //     }
    //   }
    //   return true;
    // }

    StatusObject Handler::ExtractStatus() const
    {
        // StatusObject obj{{"permitExit", permit_exit}, {"ip", if_addr.ToString()}};
        // StatusObject exitsObj{};
        // for (const auto& item : active_exits)
        // {
        //   exitsObj[item.first.ToString()] = item.second->ExtractStatus();
        // }
        // obj["exits"] = exitsObj;
        return {};
    }

    // bool Handler::should_hook_dns_msg(const dns::Message& msg) const
    // {
    //   if (msg.questions.size() == 0)
    //     return false;
    //   // always hook ptr for ranges we own
    //   if (msg.questions[0].qtype == dns::qTypePTR)
    //   {
    //     if (auto ip = dns::DecodePTR(msg.questions[0].qname))
    //       return ip_range.Contains(*ip);
    //     return false;
    //   }
    //   if (msg.questions[0].qtype == dns::qTypeA || msg.questions[0].qtype == dns::qTypeCNAME
    //       || msg.questions[0].qtype == dns::qTypeAAAA)
    //   {
    //     if (msg.questions[0].IsName("localhost.loki"))
    //       return true;
    //     if (msg.questions[0].HasTLD(".snode"))
    //       return true;
    //   }
    //   return false;
    // }

    // bool Handler::MaybeHookDNS(
    //     std::shared_ptr<dns::PacketSource_Base> source,
    //     const dns::Message& query,
    //     const SockAddr& to,
    //     const SockAddr& from)
    // {
    //   if (not ShouldHookDNSMessage(query))
    //     return false;

    //   (void)source;
    //   (void)to;
    //   (void)from;

    //   // auto job = std::make_shared<dns::QueryJob>(source, query, to, from);
    //   // if (not HandleHookedDNSMessage(query, [job](auto msg) { job->SendReply(msg.ToBuffer());
    //   }))
    //   //   job->Cancel();
    //   return true;
    // }

    // bool Handler::handle_hooked_dns_msg(dns::Message msg, std::function<void(dns::Message)>
    // reply)
    // {
    //   if (msg.questions[0].qtype == dns::qTypePTR)
    //   {
    //     auto ip = dns::DecodePTR(msg.questions[0].qname);
    //     if (not ip)
    //       return false;
    //     if (ip == _if_addr)
    //     {
    //       RouterID us = _router.pubkey();
    //       msg.AddAReply(us.ToString(), 300);
    //     }
    //     else
    //     {
    //       auto itr = ip_to_key.find(*ip);
    //       if (itr != ip_to_key.end() && snode_keys.find(itr->second) != snode_keys.end())
    //       {
    //         RouterID them{itr->second.data()};
    //         msg.AddAReply(them.ToString());
    //       }
    //       else
    //         msg.AddNXReply();
    //     }
    //   }
    //   else if (msg.questions[0].qtype == dns::qTypeCNAME)
    //   {
    //     if (msg.questions[0].IsName("random.snode"))
    //     {
    //       if (auto random = _router.GetRandomGoodRouter())
    //         msg.AddCNAMEReply(random->ToString(), 1);
    //       else
    //         msg.AddNXReply();
    //     }
    //     else if (msg.questions[0].IsName("localhost.loki"))
    //     {
    //       RouterID us = _router.pubkey();
    //       msg.AddAReply(us.ToString(), 1);
    //     }
    //     else
    //       msg.AddNXReply();
    //   }
    //   else if (msg.questions[0].qtype == dns::qTypeA || msg.questions[0].qtype == dns::qTypeAAAA)
    //   {
    //     const bool isV6 = msg.questions[0].qtype == dns::qTypeAAAA;
    //     const bool isV4 = msg.questions[0].qtype == dns::qTypeA;
    //     if (msg.questions[0].IsName("random.snode"))
    //     {
    //       if (auto random = _router.GetRandomGoodRouter())
    //       {
    //         // TODO:
    //         // msg.AddCNAMEReply(random->ToString(), 1);
    //         // auto ip = ObtainServiceNodeIP(*random);
    //         // msg.AddINReply(ip, false);
    //       }
    //       else
    //         msg.AddNXReply();
    //       reply(msg);
    //       return true;
    //     }
    //     if (msg.questions[0].IsName("localhost.loki"))
    //     {
    //       msg.AddINReply(if_addr(), isV6);
    //       reply(msg);
    //       return true;
    //     }
    //     // forward dns for snode
    //     RouterID r;
    //     if (r.from_snode_address(msg.questions[0].Name()))
    //     {
    //       huint128_t ip;
    //       PubKey pubKey(r);
    //       if (isV4 && supports_ipv6())
    //       {
    //         msg.hdr_fields |= dns::flags_QR | dns::flags_AA | dns::flags_RA;
    //       }
    //       else if (snode_keys.find(pubKey) == snode_keys.end())
    //       {
    //         // we do not have it mapped, async obtain it
    //         ObtainSNodeSession(
    //             r,
    //             [&, msg = std::make_shared<dns::Message>(msg), reply](
    //                 std::shared_ptr<session::BaseSession> session) {
    //               if (session && session->IsReady())
    //               {
    //                 msg->AddINReply(key_to_IP[pubKey], isV6);
    //               }
    //               else
    //               {
    //                 msg->AddNXReply();
    //               }
    //               reply(*msg);
    //             });
    //         return true;
    //       }
    //       else
    //       {
    //         // we have it mapped already as a service node
    //         auto itr = key_to_IP.find(pubKey);
    //         if (itr != key_to_IP.end())
    //         {
    //           ip = itr->second;
    //           msg.AddINReply(ip, isV6);
    //         }
    //         else  // fallback case that should never happen (probably)
    //           msg.AddNXReply();
    //       }
    //     }
    //     else
    //       msg.AddNXReply();
    //   }
    //   reply(msg);
    //   return true;
    // }

    // void Handler::ObtainSNodeSession(const RouterID& rid)
    // {
    //   (void)rid;
    //   // if (not _router.node_db()->is_connection_allowed(rid))
    //   // {
    //   //   obtain_cb(nullptr);
    //   //   return;
    //   // }
    //   // ObtainServiceNodeIP(rid);
    //   // snode_sessions[rid]->AddReadyHook(obtain_cb);
    // }

    bool Handler::Start()
    {
        // map our address
        // const PubKey us(_router.pubkey());
        // const huint128_t ip = if_addr();
        // key_to_IP[us] = ip;
        // ip_to_key[ip] = us;
        // ip_activity[ip] = std::numeric_limits<llarp_time_t>::max();
        // snode_keys.insert(us);

        // TODO: move this into router
        //     if (should_init_tun)
        //     {
        //       vpn::InterfaceInfo info;
        //       info.ifname = if_name;
        //       info.addrs.emplace_back(ip_range);

        //       if_net = _router.vpn_platform()->CreateInterface(std::move(info), _router);
        //       if (not if_net)
        //       {
        //         llarp::LogError("Could not create interface");
        //         return false;
        //       }
        //       if (not _router.loop()->add_network_interface(
        //               if_net, [this](net::IPPacket pkt) { OnInetPacket(std::move(pkt)); }))
        //       {
        //         llarp::LogWarn("Could not create tunnel for exit endpoint");
        //         return false;
        //       }

        //       // _router.loop()->add_ticker([this] { Flush(); });
        // #ifndef _WIN32
        //       resolver =
        //           std::make_shared<dns::Server>(_router.loop(), dns_conf,
        //           if_nametoindex(if_name.c_str()));
        //       resolver->Start();

        // #endif
        //     }
        return true;
    }

    // bool Handler::HasLocalMappedAddrFor(const PubKey& pk) const
    // {
    //   return key_to_IP.find(pk) != key_to_IP.end();
    // }

    // huint128_t
    // Handler::ObtainServiceNodeIP(const RouterID& other)  // "find router"
    // {
    //   const PubKey pubKey{other};
    //   const PubKey us{_router.pubkey()};
    //   // just in case
    //   if (pubKey == us)
    //     return if_addr;

    //   huint128_t ip = GetIPForIdent(pubKey);
    //   // if (snode_keys.emplace(pubKey).second)
    //   // {
    //   //   auto session = std::make_shared<exit::SNodeSession>(
    //   //       other,
    //   //       [this, ip](const auto& buf) { return QueueSNodePacket(buf, ip); },
    //   //       _router,
    //   //       2,
    //   //       1,
    //   //       true,
    //   //       this);
    //   //   // this is a new service node make an outbound session to them
    //   //   snode_sessions[other] = session;
    //   // }
    //   return ip;
    // }

}  // namespace llarp::service
