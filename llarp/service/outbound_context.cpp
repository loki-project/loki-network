#include "outbound_context.hpp"

#include "async_key_exchange.hpp"
#include "endpoint.hpp"
#include "endpoint_util.hpp"
#include "protocol_type.hpp"

#include <llarp/messages/common.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/router/router.hpp>

#include <algorithm>
#include <random>

namespace llarp::service
{
    bool OutboundContext::Stop()
    {
        marked_bad = true;
        return path::PathBuilder::Stop();
    }

    bool OutboundContext::IsDone(std::chrono::milliseconds now) const
    {
        (void)now;
        return AvailablePaths(path::ePathRoleAny) == 0 && ShouldRemove();
    }

    constexpr auto OutboundContextNumPaths = 4;

    OutboundContext::OutboundContext(const IntroSet& introset, Endpoint* parent)
        : path::PathBuilder{parent->router(), OutboundContextNumPaths, parent->num_hops},
          ep{*parent},
          current_intro{introset},
          location{current_intro.address_keys.Addr().ToKey()},
          addr{current_intro.address_keys.Addr()},
          remote_identity{current_intro.address_keys},
          created_at{ep.Now()}
    {
        assert(not introset.intros.empty());
        updatingIntroSet = false;

        // pick random first intro
        next_intro = *std::next(
            introset.intros.begin(),
            std::uniform_int_distribution<size_t>{0, introset.intros.size() - 1}(llarp::csrng));
        current_tag.Randomize();
        last_shift = Now();
        // add send and connect timeouts to the parent endpoints path alignment timeout
        // this will make it so that there is less of a chance for timing races
        send_timeout += parent->PathAlignmentTimeout();
        connect_timeout += parent->PathAlignmentTimeout();
    }

    OutboundContext::~OutboundContext() = default;

    /// actually swap intros
    void OutboundContext::swap_intros()
    {
        if (remote_intro != next_intro)
        {
            remote_intro = next_intro;
            ep.PutSenderFor(current_tag, current_intro.address_keys, false);
            ep.PutIntroFor(current_tag, remote_intro);
            ShiftIntroRouter(next_intro.router);
            // if we have not made a handshake to the remote endpoint do so
            if (not generated_convo_intro)
            {
                KeepAlive();
            }
        }
    }

    Address OutboundContext::Addr() const
    {
        return addr;
    }

    bool OutboundContext::ReadyToSend() const
    {
        if (marked_bad)
            return false;
        if (remote_intro.router.IsZero())
            return false;
        return sent_convo_intro and GetPathByRouter(remote_intro.router);
    }

    void OutboundContext::ShiftIntroRouter(const RouterID r)
    {
        const auto now = Now();
        Introduction selectedIntro{};
        for (const auto& intro : current_intro.intros)
        {
            if (intro.expiry > selectedIntro.expiry and intro.router != r)
            {
                selectedIntro = intro;
            }
        }
        if (selectedIntro.router.IsZero() || selectedIntro.ExpiresSoon(now))
            return;
        next_intro = selectedIntro;
        last_shift = now;
    }

    void OutboundContext::HandlePathBuildTimeout(std::shared_ptr<path::Path> p)
    {
        ShiftIntroRouter(p->Endpoint());
        path::PathBuilder::HandlePathBuildTimeout(p);
    }

    void OutboundContext::HandlePathBuildFailedAt(std::shared_ptr<path::Path> p, RouterID hop)
    {
        if (p->Endpoint() == hop)
        {
            // shift intro when we fail at the pivot
            ShiftIntroRouter(p->Endpoint());
        }
        path::PathBuilder::HandlePathBuildFailedAt(p, hop);
    }

    void OutboundContext::HandlePathBuilt(std::shared_ptr<path::Path> p)
    {
        path::PathBuilder::HandlePathBuilt(p);
        // p->SetDataHandler([self = weak_from_this()](auto path, auto frame) {
        //   if (auto ptr = self.lock())
        //     return ptr->HandleHiddenServiceFrame(path, frame);
        //   return false;
        // });
        // p->SetDropHandler([self = weak_from_this()](auto path, auto id, auto seqno) {
        //   if (auto ptr = self.lock())
        //     return ptr->HandleDataDrop(path, id, seqno);
        //   return false;
        // });
        if (marked_bad)
        {
            // ignore new path if we are marked dead
            LogInfo(Name(), " marked bad, ignoring new path");
            p->EnterState(path::PathStatus::IGNORE, Now());
        }
        else if (p->Endpoint() == next_intro.router)
        {
            // we now have a path to the next intro, swap intros
            swap_intros();
        }
    }

    std::string OutboundContext::Name() const
    {
        return "OBContext:" + current_intro.address_keys.Addr().to_string();
    }

    // TODO: it seems a lot of this logic is duplicated in service/endpoint
    void OutboundContext::UpdateIntroSet()
    {
        constexpr auto IntrosetUpdateInterval = 10s;
        const auto now = Now();
        if (updatingIntroSet or marked_bad or now < last_introset_update + IntrosetUpdateInterval)
            return;

        log::info(logcat, "{} updating introset", Name());
        last_introset_update = now;

        const auto paths = GetManyPathsWithUniqueEndpoints(&ep, 2, location);
        uint64_t relayOrder = 0;

        for (const auto& path : paths)
        {
            path->find_intro(location, false, relayOrder, [this](std::string resp) mutable {
                if (marked_bad)
                {
                    log::info(logcat, "Outbound context has been marked bad (whatever that means)");
                    return;
                }

                updatingIntroSet = false;

                // TODO: this parsing is probably elsewhere, may need DRYed
                std::string introset;
                try
                {
                    oxenc::bt_dict_consumer btdc{resp};
                    auto status = btdc.require<std::string_view>(messages::STATUS_KEY);
                    if (status != "OK"sv)
                    {
                        log::info(logcat, "Error in find intro set response: {}", status);
                        return;
                    }
                    introset = btdc.require<std::string>("INTROSET");
                }
                catch (...)
                {
                    log::warning(logcat, "Failed to parse find name response!");
                    throw;
                }

                service::EncryptedIntroSet enc{introset};
                const auto intro = enc.decrypt(PubKey{addr.as_array()});

                if (intro.time_signed == 0s)
                {
                    log::warning(logcat, "{} recieved introset with zero timestamp");
                    return;
                }
                if (current_intro.time_signed > intro.time_signed)
                {
                    log::info(logcat, "{} received outdated introset; dropping", Name());
                    return;
                }

                // don't "shift" to the same intro we're already using...
                if (current_intro == intro)
                    return;

                if (intro.IsExpired(llarp::time_now_ms()))
                {
                    log::warning(logcat, "{} received expired introset", Name());
                    return;
                }

                current_intro = intro;
                ShiftIntroRouter();
            });
        }
    }

    StatusObject OutboundContext::ExtractStatus() const
    {
        auto obj = path::PathBuilder::ExtractStatus();
        obj["current_tag"] = current_tag.ToHex();
        obj["remote_intro"] = remote_intro.ExtractStatus();
        obj["session_created"] = to_json(created_at);
        obj["last_send"] = to_json(last_send);
        obj["lastRecv"] = to_json(last_inbound_traffic);
        obj["lastIntrosetUpdate"] = to_json(last_introset_update);
        obj["marked_bad"] = marked_bad;
        obj["last_shift"] = to_json(last_shift);
        obj["remote_identityity"] = addr.to_string();
        obj["currentRemote_introset"] = current_intro.ExtractStatus();
        obj["nextIntro"] = next_intro.ExtractStatus();
        obj["readyToSend"] = ReadyToSend();
        return obj;
    }

    void OutboundContext::KeepAlive()
    {
        std::string buf(64, '\0');

        crypto::randomize(reinterpret_cast<unsigned char*>(buf.data()), buf.size());

        send_packet_to_remote(buf);
        last_keep_alive = Now();
    }

    bool OutboundContext::Pump(std::chrono::milliseconds now)
    {
        if (ReadyToSend() and remote_intro.router.IsZero())
        {
            swap_intros();
        }
        if (ReadyToSend())
        {
            // if we dont have a cached session key after sending intro we are in a fugged state so
            // expunge
            SharedSecret discardme;
            if (not ep.GetCachedSessionKeyFor(current_tag, discardme))
            {
                LogError(Name(), " no cached key after sending intro, we are in a fugged state, oh no");
                return true;
            }
        }

        if (got_inbound_traffic and last_inbound_traffic + send_timeout <= now)
        {
            // timeout on other side
            UpdateIntroSet();
            ShiftIntroRouter(remote_intro.router);
        }
        // check for stale intros
        // update the introset if we think we need to
        if (current_intro.HasStaleIntros(now, path::INTRO_PATH_SPREAD)
            or remote_intro.ExpiresSoon(now, path::INTRO_PATH_SPREAD))
        {
            UpdateIntroSet();
            ShiftIntroduction(false);
        }

        if (ReadyToSend())
        {
            if (not remote_intro.router.IsZero() and not GetPathByRouter(remote_intro.router))
            {
                // pick another good intro if we have no path on our current intro
                std::vector<Introduction> otherIntros;
                ForEachPath([now, router = remote_intro.router, &otherIntros](auto path) {
                    if (path and path->IsReady() and path->Endpoint() != router
                        and not path->ExpiresSoon(now, path::INTRO_PATH_SPREAD))
                    {
                        otherIntros.emplace_back(path->intro);
                    }
                });
                if (not otherIntros.empty())
                {
                    std::shuffle(otherIntros.begin(), otherIntros.end(), llarp::csrng);
                    remote_intro = otherIntros[0];
                }
            }
        }

        if (ReadyToSend())
        {
            const auto path = GetPathByRouter(remote_intro.router);
            if (not path)
            {
                LogWarn(Name(), " ready but no path to ", remote_intro.router, " ???");
                return true;
            }
        }

        const auto timeout = std::max(last_send, last_inbound_traffic);
        if (last_send > 0s and now >= timeout + (send_timeout / 2))
        {
            // send a keep alive to keep this session alive
            KeepAlive();
            if (marked_bad)
            {
                LogWarn(Name(), " keepalive timeout hit");
                return true;
            }
        }

        // check for half open state where we can send but we get nothing back
        if (last_inbound_traffic == 0s and now - created_at > connect_timeout)
        {
            LogWarn(Name(), " half open state, we can send but we got nothing back");
            return true;
        }
        // if we are dead return true so we are removed
        const bool removeIt = timeout > 0s ? (now >= timeout && now - timeout > send_timeout)
                                           : (now >= created_at && now - created_at > connect_timeout);
        if (removeIt)
        {
            LogInfo(Name(), " session is stale");
            return true;
        }
        return false;
    }

    std::optional<std::vector<RemoteRC>> OutboundContext::GetHopsForBuild()
    {
        if (next_intro.router.IsZero())
        {
            ShiftIntroduction(false);
        }
        if (next_intro.router.IsZero())
            return std::nullopt;
        return GetHopsAlignedToForBuild(next_intro.router, ep.SnodeBlacklist());
    }

    bool OutboundContext::ShouldBuildMore(std::chrono::milliseconds now) const
    {
        if (marked_bad or path::PathBuilder::BuildCooldownHit(now))
            return false;

        if (NumInStatus(path::PathStatus::BUILDING) >= std::max(num_paths_desired / size_t{2}, size_t{1}))
            return false;

        size_t numValidPaths = 0;
        bool havePathToNextIntro = false;
        ForEachPath([now, this, &havePathToNextIntro, &numValidPaths](std::shared_ptr<path::Path> path) {
            if (not path->IsReady())
                return;
            if (not path->intro.ExpiresSoon(now, path::DEFAULT_LIFETIME - path::INTRO_PATH_SPREAD))
            {
                numValidPaths++;
                if (path->intro.router == next_intro.router)
                    havePathToNextIntro = true;
            }
        });
        return numValidPaths < num_paths_desired or not havePathToNextIntro;
    }

    bool OutboundContext::ShiftIntroduction(bool rebuild)
    {
        bool success = false, shifted = false;
        const auto now = Now();
        auto shift_timeout = send_timeout * 5 / 2;

        if (abs(now - last_shift) < shift_timeout)
            return false;

        std::vector<Introduction> intros = current_intro.intros;

        // don't consider intros for which we don't have the RC for the pivot
        auto itr = intros.begin();
        while (itr != intros.end())
        {
            if (not ep.router()->node_db()->has_rc(itr->router))
            {
                itr = intros.erase(itr);
                continue;
            }
            itr++;
        }

        if (intros.size() > 1)
        {
            std::shuffle(intros.begin(), intros.end(), llarp::csrng);
        }

        // to find a intro on the same router as before that is newer
        for (const auto& intro : intros)
        {
            if (intro.ExpiresSoon(now))
                continue;
            if (ep.SnodeBlacklist().count(intro.router))
                continue;
            if (remote_intro.router == intro.router)
            {
                if (intro.expiry > next_intro.expiry)
                {
                    success = true;
                    next_intro = intro;
                }
            }
        }
        if (!success)
        {
            /// pick newer intro not on same router
            for (const auto& intro : intros)
            {
                if (ep.SnodeBlacklist().count(intro.router))
                    continue;
                if (intro.ExpiresSoon(now))
                    continue;
                if (next_intro != intro)
                {
                    if (intro.expiry > next_intro.expiry)
                    {
                        shifted = intro.router != next_intro.router;
                        next_intro = intro;
                        success = true;
                    }
                }
            }
        }
        if (next_intro.router.IsZero())
            return false;
        if (shifted)
            last_shift = now;
        if (rebuild && !BuildCooldownHit(Now()))
            BuildOneAlignedTo(next_intro.router);
        return success;
    }

    void OutboundContext::HandlePathDied(std::shared_ptr<path::Path> path)
    {
        // unconditionally update introset
        UpdateIntroSet();
        const RouterID endpoint{path->Endpoint()};
        // if a path to our current intro died...
        if (endpoint == remote_intro.router)
        {
            // figure out how many paths to this router we have
            size_t num = 0;
            ForEachPath([&](const std::shared_ptr<path::Path>& p) {
                if (p->Endpoint() == endpoint && p->IsReady())
                    ++num;
            });
            if (num == 0)
            {
                // we have no more paths to this endpoint so we want to pivot off of it
                ShiftIntroRouter(endpoint);
                if (next_intro.router != endpoint)
                    BuildOneAlignedTo(next_intro.router);
            }
        }
    }

    bool OutboundContext::ShouldKeepAlive(std::chrono::milliseconds now) const
    {
        const auto SendKeepAliveInterval = send_timeout / 2;

        if (not got_inbound_traffic)
            return false;

        if (last_inbound_traffic == 0s)
            return false;

        return (now - last_keep_alive) >= SendKeepAliveInterval;
    }

    void OutboundContext::Tick(llarp_time_t now)
    {
        path::PathBuilder::Tick(now);

        if (ShouldKeepAlive(now))
            KeepAlive();
    }

    void OutboundContext::send_auth_async(std::function<void(std::string, bool)> resultHandler)
    {
        if (const auto maybe = ep.MaybeGetAuthInfoForEndpoint(remote_identity.Addr()))
            gen_intro_async_impl(maybe->token, std::move(resultHandler));
        else
            resultHandler("No auth needed", true);
    }

    void OutboundContext::gen_intro_async_impl(std::string payload, std::function<void(std::string, bool)> func)
    {
        auto path = GetPathByRouter(remote_intro.router);

        if (path == nullptr)
        {
            log::warning(logcat, "{} unexpectedly has no path to remote {}", Name(), remote_intro.router);
            return;
        }

        auto frame = std::make_shared<ProtocolFrameMessage>();
        frame->clear();

        auto ex = std::make_shared<AsyncKeyExchange>(
            ep.Loop(), remote_identity, ep.GetIdentity(), current_intro.sntru_pubkey, remote_intro, &ep, current_tag);

        if (const auto maybe = ep.MaybeGetAuthInfoForEndpoint(remote_identity.Addr()); not maybe)
            ex->msg.proto = ProtocolType::Auth;

        ex->hook = [this, path, cb = std::move(func)](auto frame) mutable {
            auto hook = [&, frame, path](std::string resp) {
                // TODO: revisit this
                (void)resp;
                ep.HandleHiddenServiceFrame(path, *frame.get());
            };

            if (path->send_path_control_message("convo_intro", frame->bt_encode(), hook))
                sent_convo_intro = true;
        };

        ex->msg.put_buffer(payload);
        ex->msg.introReply = path->intro;
        frame->path_id = ex->msg.introReply.path_id;
        frame->flag = 0;
        generated_convo_intro = true;
        // ensure we have a sender put for this convo tag
        ep.PutSenderFor(current_tag, current_intro.address_keys, false);
        // encrypt frame async
        ep.router()->queue_work([ex, frame] { return AsyncKeyExchange::Encrypt(ex, frame); });

        log::info(logcat, "{} send convo intro frame for tag {}", Name(), current_tag);
    }

    void OutboundContext::gen_intro_async(std::string payload)
    {
        if (generated_convo_intro)
        {
            LogWarn(Name(), " dropping packet as we are not fully handshaked right now");
            return;
        }
        if (remote_intro.router.IsZero())
        {
            LogWarn(Name(), " dropping convo intro frame we have no intro ready yet");
            return;
        }

        gen_intro_async_impl(std::move(payload));
    }

    void OutboundContext::send_packet_to_remote(std::string buf)
    {
        if (sent_convo_intro)
        {
            encrypt_and_send(std::move(buf));
            return;
        }

        if (generated_convo_intro)
        {
            log::warning(logcat, "{} has generated an unsent initial handshake; dropping packet");
            return;
        }

        gen_intro_async(std::move(buf));
    }

    void OutboundContext::encrypt_and_send(std::string buf)
    {
        SharedSecret shared;
        auto f = std::make_shared<ProtocolFrameMessage>();
        f->flag = 0;
        f->nonce.Randomize();
        f->convo_tag = current_tag;

        auto path = GetPathByRouter(remote_intro.router);

        if (!path)
        {
            ShiftIntroRouter(remote_intro.router);
            log::warning(logcat, "{} cannot encrypt and send: no path for intro {}", Name(), remote_intro);
            return;
        }

        if (!ep.GetCachedSessionKeyFor(f->convo_tag, shared))
        {
            log::warning(logcat, "{} could not send; no cached session keys for tag {}", Name(), f->convo_tag);
            return;
        }

        auto msg = std::make_shared<ProtocolMessage>();
        ep.PutIntroFor(f->convo_tag, remote_intro);
        ep.PutReplyIntroFor(f->convo_tag, path->intro);

        msg->introReply = path->intro;
        f->path_id = msg->introReply.path_id;
        msg->sender = ep.GetIdentity().pub;
        msg->tag = f->convo_tag;
        msg->put_buffer(buf);

        _router->loop()->call_soon([this, f, msg, shared, path]() {
            if (f->EncryptAndSign(*msg, shared, ep.GetIdentity()))
                path->send_path_control_message("convo_intro", msg->bt_encode());
            else
                log::warning(logcat, "{} failed to sign protocol frame message!", Name());
        });
    }

}  // namespace llarp::service
