#include "endpoint.hpp"

#include "endpoint_state.hpp"
#include "info.hpp"
#include "protocol.hpp"

#include <llarp/dht/key.hpp>
#include <llarp/link/contacts.hpp>
#include <llarp/link/tunnel.hpp>
#include <llarp/messages/common.hpp>
#include <llarp/net/ip.hpp>
#include <llarp/net/ip_range.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path.hpp>
#include <llarp/profiling.hpp>
#include <llarp/router/route_poker.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/priority_queue.hpp>

#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace llarp::service
{
    static auto logcat = log::Cat("endpoint");

    Endpoint::Endpoint(Router& r) : path::PathHandler{r, 3, path::DEFAULT_LEN}
    {
        // if (Loop()->MaybeGetUVWLoop())
        //   _tunnel_manager = std::make_unique<link::TunnelManager>(*this);
    }

    bool Endpoint::Configure(const NetworkConfig& conf, [[maybe_unused]] const DnsConfig& dnsConf)
    {
        if (conf.paths.has_value())
            num_paths_desired = *conf.paths;

        if (conf.hops.has_value())
            num_hops = *conf.hops;

        // TODO: move this with the exit map
        // conf.exit_map.ForEachEntry(
        //     [&](const IPRange& range, const service::Address& addr) { MapExitRange(range, addr);
        //     });

        // TODO: config exit auths
        // for (auto [exit, auth] : conf.exit_auths)
        // {
        //   SetAuthInfoForEndpoint(exit, auth);
        // }

        conf.ons_range_map.ForEachEntry([&](const IP_range_deprecated& range, const std::string& name) {
            std::optional<auth::AuthInfo> auth;
            const auto itr = conf.ons_exit_auths.find(name);
            if (itr != conf.ons_exit_auths.end())
                auth = itr->second;
            (void)range;
            // _startup_ons_mappings[name] = std::make_pair(range, auth);
        });

        // return _state->Configure(conf);
        return true;
    }

    bool Endpoint::is_ready() const
    {
        // const auto now = llarp::time_now_ms();
        // if (intro_set().intros.empty())
        //   return false;
        // if (intro_set().IsExpired(now))
        //   return false;
        return true;
    }

    // bool Endpoint::HasPendingRouterLookup(const RouterID remote) const
    // {
    //   const auto& routers = _state->pending_routers;
    //   return routers.find(remote) != routers.end();
    // }

    // void Endpoint::map_exit(
    //     std::string name,
    //     std::string token,
    //     std::vector<IPRange> ranges,
    //     std::function<void(bool, std::string)> result_handler)
    // {
    //   if (ranges.empty())
    //   {
    //     result_handler(false, "no ranges provided");
    //     return;
    //   }

    //   lookup_name(
    //       name,
    //       [ptr = std::static_pointer_cast<Endpoint>(get_self()),
    //        name,
    //        auth = auth::AuthInfo{token},
    //        ranges,
    //        result_handler,
    //        poker = router().route_poker()](std::string name_result, bool success) mutable {
    //         if (not success)
    //         {
    //           result_handler(false, "Exit {} not found!"_format(name));
    //           return;
    //         }

    //         if (auto saddr = service::Address(); saddr.FromString(name_result))
    //         {
    //           ptr->SetAuthInfoForEndpoint(saddr, auth);
    //           ptr->MarkAddressOutbound(saddr);

    //           auto result = ptr->EnsurePathToService(
    //               saddr,
    //               [ptr, name, name_result, ranges, result_handler, poker](
    //                   auto addr, OutboundContext* ctx) {
    //                 if (ctx == nullptr)
    //                 {
    //                   result_handler(
    //                       false, "could not establish flow to {} ({})"_format(name_result,
    //                       name));
    //                   return;
    //                 }

    //                 // make a lambda that sends the reply after doing auth
    //                 auto apply_result = [ptr, poker, addr, result_handler, ranges](
    //                                         std::string result, bool success) {
    //                   if (success)
    //                   {
    //                     for (const auto& range : ranges)
    //                       ptr->MapExitRange(range, addr);

    //                     if (poker)
    //                       poker->put_up();
    //                   }

    //                   result_handler(success, result);
    //                 };

    //                 ctx->send_auth_async(apply_result);
    //               },
    //               ptr->PathAlignmentTimeout());

    //           if (not result)
    //             result_handler(false, "Could not build path to {} ({})"_format(name_result,
    //             name));
    //         }
    //       });
    // }

    // void Endpoint::LookupServiceAsync(
    //     std::string name,
    //     std::string service,
    //     std::function<void(std::vector<dns::SRVData>)> resultHandler)
    // {
    //   // A lookup goes through a chain of events:
    //   // - see if the name is ONS, and if so resolve it to a ADDR.loki
    //   // - once we've resolved to ADDR.loki then initiate a path to it
    //   // - once we have a path, consult the remote's introset to pull out the SRV records
    //   // If we fail along the way (e.g. it's a .snode, we can't build a path, or whatever else)
    //   then
    //   // we invoke the resultHandler with an empty vector.
    //   lookup_name(
    //       name,
    //       [this, resultHandler, service = std::move(service)](
    //           std::string name_result, bool success) mutable {
    //         if (!success)
    //           return resultHandler({});

    //         std::string name;
    //         try
    //         {
    //           oxenc::bt_dict_consumer btdc{name_result};
    //           name = btdc.require<std::string>("NAME");
    //         }
    //         catch (...)
    //         {
    //           log::warning(logcat, "Failed to parse find name response!");
    //           return resultHandler({});
    //         }

    //         auto saddr = service::Address();
    //         if (!saddr.FromString(name))
    //           return resultHandler({});  // Not a regular ADDR.loki so doesn't support SRV

    //         // initiate path build
    //         const auto build_started = EnsurePathTo(
    //             saddr,
    //             [this, address = std::move(saddr), resultHandler, service = std::move(service)](
    //                 auto maybe_tag) {
    //               if (not maybe_tag)
    //                 return resultHandler({});

    //               // we can probably get this info before we have a path to them but we do this
    //               after
    //               // we have a path so when we send the DNS response back they can talk to them
    //               // immediately
    //               const auto& container = _state->remote_sessions;
    //               if (auto itr = container.find(address); itr != container.end())
    //                 // parse the stuff we need from this guy
    //                 resultHandler(itr->second->GetCurrentIntroSet().GetMatchingSRVRecords(service));
    //               else
    //                 resultHandler({});
    //             },
    //             PathAlignmentTimeout());

    //         // on path build start fail short circuit
    //         if (not build_started)
    //           resultHandler({});
    //       });
    // }

    bool Endpoint::IntrosetIsStale() const
    {
        // return intro_set().HasExpiredIntros(llarp::time_now_ms());
        return true;
    }

    StatusObject Endpoint::ExtractStatus() const
    {
        // auto obj = path::PathBuilder::ExtractStatus();
        // obj["exitMap"] = _exit_map.ExtractStatus();
        // obj["identity"] = _identity.pub.Addr().to_string();
        // obj["networkReady"] = ReadyForNetwork();

        return {};
    }

    void Endpoint::Tick(llarp_time_t)
    {
        const auto now = llarp::time_now_ms();
        path::PathHandler::Tick(now);
        // publish descriptors
        // if (should_publish_intro(now))
        // {
        //   regen_and_publish_introset();
        // }
        // // decay introset lookup filter
        // _introset_lookup_filter.Decay(now);
        // // expire name cache
        // _state->nameCache.Decay(now);
        // // expire snode sessions
        // EndpointUtil::ExpireSNodeSessions(now, _state->snode_sessions);
        // // expire pending router lookups

        // // deregister dead sessions
        // EndpointUtil::DeregisterDeadSessions(now, _state->dead_sessions);
        // // tick remote sessions
        // EndpointUtil::TickRemoteSessions(
        //     now, _state->remote_sessions, _state->dead_sessions, Sessions());
        // // expire convotags
        // EndpointUtil::ExpireConvoSessions(now, Sessions());
    }

    uint64_t Endpoint::GenTXID()
    {
        return randint();
    }

    std::string Endpoint::name() const
    {
        return /* _state->name + ":" +  */ _identity.pub.Name();
    }

    // bool Endpoint::HasInboundConvo(const Address& addr) const
    // {
    //   for (const auto& item : Sessions())
    //   {
    //     if (item.second.remote.Addr() == addr and item.second.inbound)
    //       return true;
    //   }
    //   return false;
    // }

    // bool Endpoint::HasOutboundConvo(const Address& addr) const
    // {
    //   for (const auto& item : Sessions())
    //   {
    //     if (item.second.remote.Addr() == addr && not item.second.inbound)
    //       return true;
    //   }
    //   return false;
    // }

    size_t Endpoint::RemoveAllConvoTagsFor(service::Address remote)
    {
        (void)remote;
        size_t removed = 0;
        // auto& sessions = Sessions();
        // auto itr = sessions.begin();
        // while (itr != sessions.end())
        // {
        //   if (itr->second.remote.Addr() == remote)
        //   {
        //     itr = sessions.erase(itr);
        //     removed++;
        //   }
        //   else
        //     ++itr;
        // }
        return removed;
    }

    // void Endpoint::PutIntroFor(const SessionTag& tag, const Introduction& intro)
    // {
    //   auto& s = Sessions()[tag];
    //   s.intro = intro;
    // }

    // bool Endpoint::GetIntroFor(const SessionTag& tag, Introduction& intro) const
    // {
    //   auto itr = Sessions().find(tag);
    //   if (itr == Sessions().end())
    //     return false;
    //   intro = itr->second.intro;
    //   return true;
    // }

    // void Endpoint::PutReplyIntroFor(const SessionTag& tag, const Introduction& intro)
    // {
    //   auto itr = Sessions().find(tag);
    //   if (itr == Sessions().end())
    //   {
    //     return;
    //   }
    //   itr->second.replyIntro = intro;
    // }

    // bool Endpoint::GetReplyIntroFor(const SessionTag& tag, Introduction& intro) const
    // {
    //   auto itr = Sessions().find(tag);
    //   if (itr == Sessions().end())
    //     return false;
    //   intro = itr->second.replyIntro;
    //   return true;
    // }

    // bool Endpoint::GetConvoTagsForService(const Address& addr, std::set<ConvoTag>& tags) const
    // {
    //   return EndpointUtil::GetConvoTagsForService(Sessions(), addr, tags);
    // }

    // bool Endpoint::GetCachedSessionKeyFor(const SessionTag& tag, SharedSecret& secret) const
    // {
    //   auto itr = Sessions().find(tag);
    //   if (itr == Sessions().end())
    //     return false;
    //   secret = itr->second.sharedKey;
    //   return true;
    // }

    // void Endpoint::PutCachedSessionKeyFor(const SessionTag& tag, const SharedSecret& k)
    // {
    //   auto itr = Sessions().find(tag);
    //   if (itr == Sessions().end())
    //   {
    //     itr = Sessions().emplace(tag, Session{}).first;
    //   }
    //   itr->second.sharedKey = k;
    // }

    // void Endpoint::ConvoTagTX(const SessionTag& tag)
    // {
    //   if (Sessions().count(tag))
    //     Sessions()[tag].TX();
    // }

    // void Endpoint::ConvoTagRX(const SessionTag& tag)
    // {
    //   if (Sessions().count(tag))
    //     Sessions()[tag].RX();
    // }

    bool Endpoint::Start()
    {
        return true;
    }

    void Endpoint::regen_and_publish_introset()
    {
        // const auto now = llarp::time_now_ms();
        // _last_introset_regen_attempt = now;
        // std::set<Introduction, CompareIntroTimestamp> intros;

        // if (const auto maybe =
        //         GetCurrentIntroductionsWithFilter([now](const service::Introduction& intro) ->
        //         bool {
        //           return not intro.ExpiresSoon(now, path::INTRO_STALE_THRESHOLD);
        //         }))
        // {
        //   intros.insert(maybe->begin(), maybe->end());
        // }
        // else
        // {
        //   LogWarn(
        //       "could not publish descriptors for endpoint ",
        //       Name(),
        //       " because we couldn't get enough valid introductions");
        //   BuildOne();
        //   return;
        // }

        // intro_set().supported_protocols.clear();

        // // add supported ethertypes
        // if (HasIfAddr())
        // {
        //   if (IPRange::V4MappedRange().Contains(GetIfAddr()))
        //   {
        //     intro_set().supported_protocols.push_back(ProtocolType::TrafficV4);
        //   }
        //   else
        //   {
        //     intro_set().supported_protocols.push_back(ProtocolType::TrafficV6);
        //   }

        //   exit related stuffo
        //   if (_state->is_exit_enabled)
        //   {
        //     intro_set().supported_protocols.push_back(ProtocolType::Exit);
        //     intro_set().exit_policy = GetExitPolicy();
        //     intro_set().owned_ranges = GetOwnedRanges();
        //   }
        // }
        // // add quic ethertype if we have listeners set up
        // if (auto* quic = GetQUICTunnel())
        // {
        // // TODO:
        // if (quic->hasListeners())
        //   intro_set().supported_protocols.push_back(ProtocolType::QUIC);
        // }

        // intro_set().intros.clear();
        // for (auto& intro : intros)
        // {
        //   if (intro_set().intros.size() < num_paths_desired)
        //     intro_set().intros.emplace_back(std::move(intro));
        // }
        // if (intro_set().intros.empty())
        // {
        //   LogWarn("not enough intros to publish introset for ", Name());
        //   if (ShouldBuildMore(now))
        //     ManualRebuild(1);
        //   return;
        // }
        // auto maybe = _identity.encrypt_and_sign_introset(intro_set(), now);
        // if (not maybe)
        // {
        //   LogWarn("failed to generate introset for endpoint ", Name());
        //   return;
        // }
        // if (publish_introset(*maybe))
        // {
        //   LogInfo("(re)publishing introset for endpoint ", Name());
        // }
        // else
        // {
        //   LogWarn("failed to publish intro set for endpoint ", Name());
        // }
    }

    bool Endpoint::publish_introset(const EncryptedIntroSet& introset)
    {
        (void)introset;
        // const auto paths = GetManyPathsWithUniqueEndpoints(
        //     this, INTROSET_RELAY_REDUNDANCY, dht::Key_t{introset.derivedSigningKey.as_array()});

        // if (paths.size() != INTROSET_RELAY_REDUNDANCY)
        // {
        //   LogWarn(
        //       "Cannot publish intro set because we only have ",
        //       paths.size(),
        //       " paths, but need ",
        //       INTROSET_RELAY_REDUNDANCY);
        //   return false;
        // }

        // for (const auto& path : paths)
        // {
        //   for (size_t i = 0; i < INTROSET_REQS_PER_RELAY; ++i)
        //   {
        //     router().send_control_message(path->upstream(), "publish_intro",
        //     introset.bt_encode());
        //   }
        // }

        return true;
    }

    [[maybe_unused]] constexpr auto PublishIntrosetTimeout = 20s;

    void Endpoint::reset_path_state()
    {
        path::PathHandler::reset_path_state();
        static auto resetState = [](auto& container, auto getter) {
            std::for_each(
                container.begin(), container.end(), [getter](auto& item) { getter(item)->reset_path_state(); });
        };
        (void)resetState;
        // resetState(_state->remote_sessions, [](const auto& item) { return item.second; });
        // resetState(_state->snode_sessions, [](const auto& item) { return item.second; });
    }

    // bool Endpoint::should_publish_intro(llarp_time_t now) const
    // {
    //   if (not _publish_introset)
    //     return false;

    //   const auto lastEventAt = std::max(_state->last_publish_attempt, _state->last_publish);
    //   const auto next_pub = lastEventAt
    //       + (_state->local_introset.HasStaleIntros(now, path::INTRO_STALE_THRESHOLD)
    //              ? IntrosetPublishRetryCooldown
    //              : IntrosetPublishInterval);

    //   return now >= next_pub;
    // }

    // std::optional<std::vector<RemoteRC>> Endpoint::GetHopsForBuild()
    // {
    //   std::unordered_set<RouterID> exclude;
    //   // ForEachPath([&exclude](auto path) { exclude.insert(path->Endpoint()); });

    //   auto hook = [exclude, &r = _router](const RemoteRC& rc) -> bool {
    //     const auto& rid = rc.router_id();
    //     return not(exclude.count(rid) || r.router_profiling().IsBadForPath(rid));
    //   };

    //   if (auto maybe = router().node_db()->get_random_rc_conditional(hook))
    //     return aligned_hops_to_remote(maybe->router_id(), SnodeBlacklist());

    //   return std::nullopt;
    // }

    // constexpr auto MaxOutboundContextPerRemote = 1;

    // bool Endpoint::HasExit() const
    // {
    //   // for (const auto& [name, info] : _startup_ons_mappings)
    //   // {
    //   //   if (info.first.has_value())
    //   //     return true;
    //   // }

    //   return not _exit_map.Empty();
    // }

    auto Endpoint::GetUniqueEndpointsForLookup() const
    {
        std::unordered_set<std::shared_ptr<path::Path>, path::Endpoint_Hash, path::endpoint_comparator> paths;

        for_each_path([&paths](auto path) {
            if (path and path->IsReady())
                paths.insert(path);
        });

        return paths;
    }

    bool Endpoint::ReadyForNetwork() const
    {
        return is_ready() and ReadyToDoLookup(GetUniqueEndpointsForLookup().size());
    }

    bool Endpoint::ReadyToDoLookup(size_t num_paths) const
    {
        // Currently just checks the number of paths, but could do more checks in the future.
        return num_paths >= MIN_ONS_LOOKUP_ENDPOINTS;
    }

    bool Endpoint::HandleDataDrop(std::shared_ptr<path::Path> p, const HopID& dst, uint64_t seq)
    {
        LogWarn(name(), " message ", seq, " dropped by endpoint ", p->pivot_router_id(), " via ", dst);
        return true;
    }

    // std::unordered_map<std::string, std::string>
    // Endpoint::NotifyParams() const
    // {
    //   return {{"LOKINET_ADDR", _identity.pub.Addr().to_string()}};
    // }

    // bool Endpoint::HandleDataMessage(
    //     std::shared_ptr<path::Path> p, const PathID_t from, std::shared_ptr<ProtocolMessage> msg)
    // {
    //   PutSenderFor(msg->tag, msg->sender, true);
    //   Introduction intro = msg->introReply;

    //   if (HasInboundConvo(msg->sender.Addr()))
    //   {
    //     intro.path_id = from;
    //     intro.router = p->Endpoint();
    //   }

    //   PutReplyIntroFor(msg->tag, intro);
    //   ConvoTagRX(msg->tag);
    //   return ProcessDataMessage(msg);
    // }

    // bool Endpoint::HasPathToSNode(const RouterID ident) const
    // {
    //   auto range = _state->snode_sessions.equal_range(ident);
    //   auto itr = range.first;
    //   while (itr != range.second)
    //   {
    //     if (itr->second->IsReady())
    //     {
    //       return true;
    //     }
    //     ++itr;
    //   }
    //   return false;
    // }

    AddressVariant_t Endpoint::local_address() const
    {
        return _identity.pub.Addr();
    }

    // bool Endpoint::ProcessDataMessage(std::shared_ptr<ProtocolMessage> msg)
    // {
    //   if ((msg->proto == ProtocolType::Exit
    //        && (_state->is_exit_enabled || _exit_map.ContainsValue(msg->sender.Addr())))
    //       || msg->proto == ProtocolType::TrafficV4 || msg->proto == ProtocolType::TrafficV6
    //       || (msg->proto == ProtocolType::QUIC and _tunnel_manager))
    //   {
    //     // _inbound_queue.tryPushBack(std::move(msg));
    //     router().TriggerPump();
    //     return true;
    //   }
    //   if (msg->proto == ProtocolType::Control)
    //   {
    //     // TODO: implement me (?)
    //     // right now it's just random noise
    //     return true;
    //   }
    //   return false;
    // }

    void Endpoint::AsyncProcessAuthMessage(
        std::shared_ptr<ProtocolMessage> msg, std::function<void(std::string, bool)> hook)
    {
        // if (_auth_policy)
        // {
        //   if (not _auth_policy->auth_async_pending(msg->tag))
        //   {
        //     // do 1 authentication attempt and drop everything else
        //     _auth_policy->authenticate_async(std::move(msg), std::move(hook));
        //   }
        // }
        // else
        // {
        //   router().loop()->call([h = std::move(hook)] { h("OK", true); });
        // }
        (void)msg;
        (void)hook;
    }

    void Endpoint::SendAuthResult(
        std::shared_ptr<path::Path> path, HopID /* replyPath */, SessionTag tag, std::string result, bool success)
    {
        // not applicable because we are not an exit or don't have an endpoint auth policy
        // if ((not _state->is_exit_enabled) or _auth_policy == nullptr)
        //   return;

        ProtocolFrameMessage f{};
        f.flag = int(not success);
        f.convo_tag = tag;
        f.path_id = path->intro.path_id;
        f.nonce.Randomize();

        if (success)
        {
            ProtocolMessage msg;
            msg.put_buffer(result);

            // if (_auth_policy)
            //   msg.proto = ProtocolType::Auth;
            // else
            //   msg.proto = ProtocolType::Control;

            // if (not GetReplyIntroFor(tag, msg.introReply))
            // {
            //   LogError("Failed to send auth reply: no reply intro");
            //   return;
            // }

            // msg.sender = _identity.pub;
            // SharedSecret sessionKey{};

            // if (not GetCachedSessionKeyFor(tag, sessionKey))
            // {
            //   LogError("failed to send auth reply: no cached session key");
            //   return;
            // }

            // if (not f.EncryptAndSign(msg, sessionKey, _identity))
            // {
            //   LogError("Failed to encrypt and sign auth reply");
            //   return;
            // }
        }
        else
        {
            if (not f.Sign(_identity))
            {
                LogError("failed to sign auth reply result");
                return;
            }
        }

        // TODO:
        // _send_queue.tryPushBack(
        //     SendEvent{std::make_shared<routing::PathTransferMessage>(f, replyPath), path});
    }

    bool Endpoint::HandleHiddenServiceFrame(std::shared_ptr<path::Path> p, const ProtocolFrameMessage& frame)
    {
        (void)p;
        (void)frame;
        // if (frame.flag)
        // {
        //   // handle discard
        //   ServiceInfo si;
        //   if (!GetSenderFor(frame.convo_tag, si))
        //     return false;
        //   // verify source
        //   if (!frame.Verify(si))
        //     return false;
        //   // remove convotag it doesn't exist
        //   LogWarn("remove convotag T=", frame.convo_tag, " R=", frame.flag, " from ", si.Addr());
        //   RemoveConvoTag(frame.convo_tag);
        //   return true;
        // }
        // if (not frame.AsyncDecryptAndVerify(router().loop(), p, _identity, this))
        // {
        //   ResetConvoTag(frame.convo_tag, p, frame.path_id);
        // }
        return true;
    }

    void Endpoint::path_died(std::shared_ptr<path::Path> p)
    {
        router().router_profiling().path_timeout(p.get());
        path::PathHandler::path_died(p);
        regen_and_publish_introset();
    }

    bool Endpoint::CheckPathIsDead(std::shared_ptr<path::Path>, llarp_time_t dlt)
    {
        return dlt > path::ALIVE_TIMEOUT;
    }

    // void // Endpoint::MarkAddressOutbound(service::Address addr)
    // {
    //   _state->m_OutboundSessions.insert(addr);
    // }

    // void // Endpoint::InformPathToService(const Address remote, OutboundContext* ctx)
    // {
    //   auto& serviceLookups = _state->pending_service_lookups;
    //   auto range = serviceLookups.equal_range(remote);
    //   auto itr = range.first;
    //   while (itr != range.second)
    //   {
    //     itr->second(remote, ctx);
    //     ++itr;
    //   }
    //   serviceLookups.erase(remote);
    // }

    // bool // Endpoint::EnsurePathTo(
    //     std::variant<Address, RouterID> addr,
    //     std::function<void(std::optional<ConvoTag>)> hook,
    //     llarp_time_t timeout)
    // {
    //   if (auto ptr = std::get_if<Address>(&addr))
    //   {
    //     if (*ptr == _identity.pub.Addr())
    //     {
    //       ConvoTag tag{};

    //       if (auto maybe = GetBestConvoTagFor(*ptr))
    //         tag = *maybe;
    //       else
    //         tag.Randomize();
    //       PutSenderFor(tag, _identity.pub, true);
    //       ConvoTagTX(tag);
    //       Sessions()[tag].forever = true;
    //       Loop()->call_soon([tag, hook]() { hook(tag); });
    //       return true;
    //     }
    //     if (not WantsOutboundSession(*ptr))
    //     {
    //       // we don't want to connect back to inbound sessions
    //       hook(std::nullopt);
    //       return true;
    //     }

    //     return EnsurePathToService(
    //         *ptr,
    //         [hook](auto, auto* ctx) -> bool {
    //           if (ctx)
    //           {
    //             hook(ctx->get_current_tag());
    //             return true;
    //           }

    //           hook(std::nullopt);
    //           return false;
    //         },
    //         timeout);
    //   }
    //   if (auto ptr = std::get_if<RouterID>(&addr))
    //   {
    //     return EnsurePathToSNode(*ptr, [hook](auto, auto session, auto tag) {
    //       if (session)
    //       {
    //         hook(tag);
    //       }
    //       else
    //       {
    //         hook(std::nullopt);
    //       }
    //     });
    //   }
    //   return false;
    // }

    // bool // Endpoint::EnsurePathToSNode(
    //     const RouterID snode,
    //     std::function<void(const RouterID, std::shared_ptr<session::BaseSession>, ConvoTag)>
    //     hook)
    // {
    //   auto& nodeSessions = _state->snode_sessions;

    //   using namespace std::placeholders;
    //   if (nodeSessions.count(snode) == 0)
    //   {
    //     const auto src = xhtonl(net::TruncateV6(GetIfAddr()));
    //     const auto dst = xhtonl(net::TruncateV6(ObtainIPForAddr(snode)));

    //     auto session = std::make_shared<exit::SNodeSession>(
    //         snode,
    //         [=](const llarp_buffer_t& buf) -> bool {
    //           net::IPPacket pkt;
    //           if (not pkt.Load(buf))
    //             return false;
    //           pkt.UpdateIPv4Address(src, dst);
    //           /// TODO: V6
    //           auto itr = _state->snode_sessions.find(snode);
    //           if (itr == _state->snode_sessions.end())
    //             return false;
    //           if (const auto maybe = itr->second->CurrentPath())
    //             return HandleInboundPacket(
    //                 ConvoTag{maybe->as_array()}, pkt.ConstBuffer(), ProtocolType::TrafficV4, 0);
    //           return false;
    //         },
    //         router(),
    //         1,
    //         num_hops,
    //         false,
    //         this);
    //     _state->snode_sessions[snode] = session;
    //   }
    //   if (not router().node_db()->has_rc(snode))
    //     return false;
    //   auto range = nodeSessions.equal_range(snode);
    //   auto itr = range.first;
    //   while (itr != range.second)
    //   {
    //     if (itr->second->IsReady())
    //       hook(snode, itr->second, ConvoTag{itr->second->CurrentPath()->as_array()});
    //     else
    //     {
    //       itr->second->AddReadyHook([hook, snode](auto session) {
    //         if (session)
    //         {
    //           hook(snode, session, ConvoTag{session->CurrentPath()->as_array()});
    //         }
    //         else
    //         {
    //           hook(snode, nullptr, ConvoTag{});
    //         }
    //       });
    //       if (not itr->second->BuildCooldownHit(Now()))
    //         itr->second->BuildOne();
    //     }
    //     ++itr;
    //   }
    //   return true;
    // }

    // bool // Endpoint::EnsurePathToService(
    //     const Address remote,
    //     std::function<void(Address, OutboundContext*)> hook,
    //     [[maybe_unused]] llarp_time_t timeout)
    // {
    //   if (not WantsOutboundSession(remote))
    //   {
    //     // we don't want to ensure paths to addresses that are inbound
    //     // inform fail right away in that case
    //     hook(remote, nullptr);
    //     return false;
    //   }

    //   /// how many routers to use for lookups
    //   static constexpr size_t NumParallelLookups = 2;

    //   // add response hook to list for address.
    //   _state->pending_service_lookups.emplace(remote, hook);

    //   auto& sessions = _state->remote_sessions;
    //   {
    //     auto range = sessions.equal_range(remote);
    //     auto itr = range.first;
    //     while (itr != range.second)
    //     {
    //       if (itr->second->ReadyToSend())
    //       {
    //         InformPathToService(remote, itr->second.get());
    //         return true;
    //       }
    //       ++itr;
    //     }
    //   }
    //   /// check replay filter
    //   if (not _introset_lookup_filter.Insert(remote))
    //     return true;

    //   const auto paths = GetManyPathsWithUniqueEndpoints(this, NumParallelLookups);

    //   const dht::Key_t location = remote.ToKey();

    //   // flag to only add callback to list of callbacks for
    //   // address once.
    //   bool hookAdded = false;

    //   auto got_it = std::make_shared<bool>(false);

    //   // TODO: if all requests fail, call callback with failure?
    //   for (const auto& path : paths)
    //   {
    //     path->find_intro(location, false, 0, [hook, got_it, this](std::string resp) mutable {
    //       // asking many, use only first successful
    //       if (*got_it)
    //         return;

    //       std::string introset;

    //       try
    //       {
    //         oxenc::bt_dict_consumer btdc{resp};
    //         auto status = btdc.require<std::string_view>(messages::STATUS_KEY);
    //         if (status != "OK"sv)
    //         {
    //           log::info(logcat, "Error in find intro set response: {}", status);
    //           return;
    //         }
    //         introset = btdc.require<std::string>("INTROSET");
    //       }
    //       catch (...)
    //       {
    //         log::warning(logcat, "Failed to parse find name response!");
    //         throw;
    //       }

    //       service::EncryptedIntroSet enc{introset};
    //       router().contacts().put_intro(std::move(enc));

    //       // TODO: finish this
    //       /*
    //       if (good)
    //         *got_it = true;
    //       */
    //     });
    //   }
    //   return hookAdded;
    // }

    void Endpoint::srv_records_changed()
    {
        // auto& introset = intro_set();
        // introset.SRVs.clear();

        // for (const auto& srv : srv_records())
        //   introset.SRVs.emplace_back(srv.toTuple());

        regen_and_publish_introset();
    }

    // std::optional<SessionTag>
    // Endpoint::GetBestConvoTagFor(std::variant<Address, RouterID> remote) const
    // {
    //   // get convotag with lowest estimated RTT
    //   if (auto ptr = std::get_if<Address>(&remote))
    //   {
    //     llarp_time_t rtt = 30s;
    //     std::optional<SessionTag> ret = std::nullopt;
    //     for (const auto& [tag, session] : Sessions())
    //     {
    //       if (tag.IsZero())
    //         continue;
    //       if (session.remote.Addr() == *ptr)
    //       {
    //         if (*ptr == _identity.pub.Addr())
    //         {
    //           return tag;
    //         }
    //         if (session.inbound)
    //         {
    //           auto path = GetPathByRouter(session.replyIntro.router);
    //           // if we have no path to the remote router that's fine still use it just in case
    //           this
    //           // is the ONLY one we have
    //           if (path == nullptr)
    //           {
    //             ret = tag;
    //             continue;
    //           }

    //           if (path and path->IsReady())
    //           {
    //             const auto rttEstimate = (session.replyIntro.latency + path->intro.latency) * 2;
    //             if (rttEstimate < rtt)
    //             {
    //               ret = tag;
    //               rtt = rttEstimate;
    //             }
    //           }
    //         }
    //         else
    //         {
    //           auto range = _state->remote_sessions.equal_range(*ptr);
    //           auto itr = range.first;
    //           while (itr != range.second)
    //           {
    //             // TODO:
    //             // if (itr->second->ReadyToSend() and itr->second->estimatedRTT > 0s)
    //             // {
    //             //   if (itr->second->estimatedRTT < rtt)
    //             //   {
    //             //     ret = tag;
    //             //     rtt = itr->second->estimatedRTT;
    //             //   }
    //             // }
    //             itr++;
    //           }
    //         }
    //       }
    //     }
    //     return ret;
    //   }
    //   if (auto* ptr = std::get_if<RouterID>(&remote))
    //   {
    //     auto itr = _state->snode_sessions.find(*ptr);
    //     if (itr == _state->snode_sessions.end())
    //       return std::nullopt;
    //     if (auto maybe = itr->second->CurrentPath())
    //       return SessionTag{maybe->as_array()};
    //   }
    //   return std::nullopt;
    // }

    // bool Endpoint::ShouldBuildMore(llarp_time_t now) const
    // {
    //   if (BuildCooldownHit(now))
    //     return false;
    //   const auto requiredPaths = std::max(num_paths_desired, path::MIN_INTRO_PATHS);
    //   if (NumInStatus(path::PathStatus::BUILDING) >= requiredPaths)
    //     return false;
    //   return NumPathsExistingAt(now + (path::DEFAULT_LIFETIME - path::INTRO_PATH_SPREAD))
    //       < requiredPaths;
    // }

    const std::shared_ptr<EventLoop>& Endpoint::loop()
    {
        return router().loop();
    }

    void Endpoint::blacklist_snode(const RouterID&)
    {
        // _state->snode_blacklist.insert(snode);
    }

    const std::set<RouterID>& Endpoint::SnodeBlacklist() const
    {
        return snode_blacklist;
    }

    // void Endpoint::MapExitRange(IPRange range, Address exit)
    // {
    //   if (not exit.IsZero())
    //     LogInfo(Name(), " map ", range, " to exit at ", exit);
    //   _exit_map.Insert(range, exit);
    // }
    // bool Endpoint::HasFlowToService(Address addr) const
    // {
    //   return HasOutboundConvo(addr) or HasInboundConvo(addr);
    // }

    // void Endpoint::UnmapExitRange(IPRange range)
    // {
    //   // unmap all ranges that fit in the range we gave
    //   _exit_map.RemoveIf([&](const auto& item) -> bool {
    //     if (not range.Contains(item.first))
    //       return false;
    //     LogInfo(Name(), " unmap ", item.first, " exit range mapping");
    //     return true;
    //   });

    //   if (_exit_map.Empty())
    //     router().route_poker()->put_down();
    // }

    // void Endpoint::UnmapRangeByExit(IPRange range, std::string exit)
    // {
    //   // unmap all ranges that match the given exit when hot swapping
    //   _exit_map.RemoveIf([&](const auto& item) -> bool {
    //     if ((range.Contains(item.first)) and (item.second.to_string() == exit))
    //     {
    //       log::info(logcat, "{} unmap {} range mapping to exit node {}", Name(), item.first,
    //       exit); return true;
    //     }
    //     return false;
    //   });

    //   if (_exit_map.Empty())
    //     router().route_poker()->put_down();
    // }

    link::TunnelManager* Endpoint::GetQUICTunnel()
    {
        return _tunnel_manager.get();
    }

}  // namespace llarp::service
