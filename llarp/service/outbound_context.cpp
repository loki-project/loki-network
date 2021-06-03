#include "outbound_context.hpp"

#include <llarp/router/abstractrouter.hpp>
#include "async_key_exchange.hpp"
#include "hidden_service_address_lookup.hpp"
#include "endpoint.hpp"
#include <llarp/nodedb.hpp>
#include <llarp/profiling.hpp>
#include <llarp/util/meta/memfn.hpp>

#include "endpoint_util.hpp"
#include "service/protocol_type.hpp"

#include <random>
#include <algorithm>

namespace llarp
{
  namespace service
  {
    bool
    OutboundContext::Stop()
    {
      markedBad = true;
      return path::Builder::Stop();
    }

    bool
    OutboundContext::IsDone(llarp_time_t now) const
    {
      (void)now;
      return AvailablePaths(path::ePathRoleAny) == 0 && ShouldRemove();
    }

    bool
    OutboundContext::ShouldBundleRC() const
    {
      return m_Endpoint->ShouldBundleRC();
    }

    bool
    OutboundContext::HandleDataDrop(path::Path_ptr p, const PathID_t& dst, uint64_t seq)
    {
      // pick another intro
      if (dst == remoteIntro.pathID && remoteIntro.router == p->Endpoint())
      {
        LogWarn(Name(), " message ", seq, " dropped by endpoint ", p->Endpoint(), " via ", dst);
        MarkCurrentIntroBad(Now());
        ShiftIntroduction(false);
        UpdateIntroSet();
        SwapIntros();
      }
      return true;
    }

    constexpr auto OutboundContextNumPaths = 2;

    OutboundContext::OutboundContext(const IntroSet& introset, Endpoint* parent)
        : path::Builder{parent->Router(), OutboundContextNumPaths, parent->numHops}
        , SendContext{introset.addressKeys, {}, this, parent}
        , location{introset.addressKeys.Addr().ToKey()}
        , addr{introset.addressKeys.Addr()}
        , currentIntroSet{introset}

    {
      updatingIntroSet = false;
      for (const auto& intro : introset.intros)
      {
        if (m_NextIntro.latency == 0s or m_NextIntro.latency > intro.latency)
          m_NextIntro = intro;
      }
      currentConvoTag.Randomize();
      lastShift = Now();
    }

    OutboundContext::~OutboundContext() = default;

    /// actually swap intros
    void
    OutboundContext::SwapIntros()
    {
      if (remoteIntro != m_NextIntro)
      {
        remoteIntro = m_NextIntro;
        m_DataHandler->PutSenderFor(currentConvoTag, currentIntroSet.addressKeys, false);
        m_DataHandler->PutIntroFor(currentConvoTag, remoteIntro);
        ShiftIntroRouter(m_NextIntro.router);
        // if we have not made a handshake to the remote endpoint do so
        if (not IntroGenerated())
        {
          KeepAlive();
        }
      }
    }

    Address
    OutboundContext::Addr() const
    {
      return addr;
    }

    bool
    OutboundContext::OnIntroSetUpdate(
        const Address&,
        std::optional<IntroSet> foundIntro,
        const RouterID& endpoint,
        llarp_time_t,
        uint64_t relayOrder)
    {
      if (markedBad)
        return true;
      updatingIntroSet = false;
      if (foundIntro)
      {
        if (foundIntro->timestampSignedAt == 0s)
        {
          LogWarn(Name(), " got introset with zero timestamp: ", *foundIntro);
          return true;
        }
        if (currentIntroSet.timestampSignedAt > foundIntro->timestampSignedAt)
        {
          LogInfo("introset is old, dropping");
          return true;
        }

        const llarp_time_t now = Now();
        if (foundIntro->IsExpired(now))
        {
          LogError("got expired introset from lookup from ", endpoint);
          return true;
        }
        currentIntroSet = *foundIntro;
        ShiftIntroRouter(RouterID{});
      }
      else if (relayOrder > 0)
      {
        ++m_LookupFails;
        LogWarn(Name(), " failed to look up introset, fails=", m_LookupFails);
      }
      return true;
    }

    bool
    OutboundContext::ReadyToSend() const
    {
      if (markedBad)
        return false;
      if (remoteIntro.router.IsZero())
        return false;
      return IntroSent();
    }

    void
    OutboundContext::ShiftIntroRouter(const RouterID r)
    {
      const auto now = Now();
      Introduction selectedIntro;
      for (const auto& intro : currentIntroSet.intros)
      {
        if (intro.expiresAt > selectedIntro.expiresAt && intro.router != r)
        {
          selectedIntro = intro;
        }
      }
      if (selectedIntro.router.IsZero() || selectedIntro.ExpiresSoon(now))
        return;
      m_NextIntro = selectedIntro;
      lastShift = now;
    }

    void
    OutboundContext::HandlePathBuildTimeout(path::Path_ptr p)
    {
      ShiftIntroRouter(p->Endpoint());
      path::Builder::HandlePathBuildTimeout(p);
    }

    void
    OutboundContext::HandlePathBuildFailedAt(path::Path_ptr p, RouterID hop)
    {
      if (p->Endpoint() == hop)
      {
        // shift intro when we fail at the pivot
        ShiftIntroRouter(p->Endpoint());
      }
      path::Builder::HandlePathBuildFailedAt(p, hop);
    }

    void
    OutboundContext::HandlePathBuilt(path::Path_ptr p)
    {
      path::Builder::HandlePathBuilt(p);
      /// don't use it if we are marked bad
      if (markedBad)
        return;
      p->SetDataHandler(util::memFn(&OutboundContext::HandleHiddenServiceFrame, this));
      p->SetDropHandler(util::memFn(&OutboundContext::HandleDataDrop, this));
      // we now have a path to the next intro, swap intros
      if (p->Endpoint() == m_NextIntro.router)
        SwapIntros();
      else
      {
        LogInfo(Name(), " built to non aligned router: ", p->Endpoint());
      }
    }

    void
    OutboundContext::AsyncGenIntro(const llarp_buffer_t& payload, ProtocolType t)
    {
      if (generatedIntro)
      {
        LogWarn(Name(), " dropping packet as we are not fully handshaked right now");
        return;
      }
      if (remoteIntro.router.IsZero())
      {
        LogWarn(Name(), " dropping intro frame we have no intro ready yet");
        return;
      }

      auto path = GetPathByRouter(remoteIntro.router);
      if (path == nullptr)
      {
        LogError(Name(), " has no path to ", remoteIntro.router, " when we should have had one");
        return;
      }
      auto frame = std::make_shared<ProtocolFrame>();
      frame->Clear();
      auto ex = std::make_shared<AsyncKeyExchange>(
          m_Endpoint->Loop(),
          remoteIdent,
          m_Endpoint->GetIdentity(),
          currentIntroSet.sntrupKey,
          remoteIntro,
          m_DataHandler,
          currentConvoTag,
          t);

      ex->hook = [self = shared_from_this(), path](auto frame) {
        if (not self->Send(std::move(frame), path))
          return;
        self->m_Endpoint->Loop()->call_later(100ms, [self]() { self->sentIntro = true; });
      };

      ex->msg.PutBuffer(payload);
      ex->msg.introReply = path->intro;
      frame->F = ex->msg.introReply.pathID;
      frame->R = 0;
      generatedIntro = true;
      // ensure we have a sender put for this convo tag
      m_DataHandler->PutSenderFor(currentConvoTag, currentIntroSet.addressKeys, false);
      // encrypt frame async
      m_Endpoint->Router()->QueueWork([ex, frame] { return AsyncKeyExchange::Encrypt(ex, frame); });

      LogInfo(Name(), " send intro frame T=", currentConvoTag);
    }

    std::string
    OutboundContext::Name() const
    {
      return "OBContext:" + currentIntroSet.addressKeys.Addr().ToString();
    }

    void
    OutboundContext::UpdateIntroSet()
    {
      constexpr auto IntrosetUpdateInterval = 10s;
      const auto now = Now();
      if (updatingIntroSet or markedBad or now < m_LastIntrosetUpdateAt + IntrosetUpdateInterval)
        return;
      LogInfo(Name(), " updating introset");
      m_LastIntrosetUpdateAt = now;
      // we want to use the parent endpoint's paths because outbound context
      // does not implement path::PathSet::HandleGotIntroMessage
      const auto paths = GetManyPathsWithUniqueEndpoints(m_Endpoint, 2, location);
      uint64_t relayOrder = 0;
      for (const auto& path : paths)
      {
        HiddenServiceAddressLookup* job = new HiddenServiceAddressLookup(
            m_Endpoint,
            util::memFn(&OutboundContext::OnIntroSetUpdate, shared_from_this()),
            location,
            PubKey{addr.as_array()},
            path->Endpoint(),
            relayOrder,
            m_Endpoint->GenTXID(),
            5s);
        relayOrder++;
        if (job->SendRequestViaPath(path, m_Endpoint->Router()))
          updatingIntroSet = true;
      }
    }

    util::StatusObject
    OutboundContext::ExtractStatus() const
    {
      auto obj = path::Builder::ExtractStatus();
      obj["estimatedRTT"] = to_json(estimatedRTT);
      obj["currentConvoTag"] = currentConvoTag.ToHex();
      obj["remoteIntro"] = remoteIntro.ExtractStatus();
      obj["sessionCreatedAt"] = to_json(createdAt);
      obj["lastGoodSend"] = to_json(lastGoodSend);
      obj["lastRecv"] = to_json(m_LastInboundTraffic);
      obj["lastIntrosetUpdate"] = to_json(m_LastIntrosetUpdateAt);
      obj["seqno"] = sequenceNo;
      obj["markedBad"] = markedBad;
      obj["lastShift"] = to_json(lastShift);
      obj["remoteIdentity"] = addr.ToString();
      obj["currentRemoteIntroset"] = currentIntroSet.ExtractStatus();
      obj["nextIntro"] = m_NextIntro.ExtractStatus();
      obj["readyToSend"] = ReadyToSend();
      std::transform(
          m_BadIntros.begin(),
          m_BadIntros.end(),
          std::back_inserter(obj["badIntros"]),
          [](const auto& item) -> util::StatusObject { return item.first.ExtractStatus(); });
      return obj;
    }

    void
    OutboundContext::KeepAlive()
    {
      Encrypted<64> tmp;
      tmp.Randomize();
      SendPacketToRemote(tmp, ProtocolType::Control);
    }

    bool
    OutboundContext::Pump(llarp_time_t now)
    {
      // we are probably dead af
      if (m_LookupFails > 16 || m_BuildFails > 10)
        return true;

      if (ReadyToSend() and remoteIntro.router.IsZero())
      {
        SwapIntros();
      }

      if ((remoteIntro.router.IsZero() or m_BadIntros.count(remoteIntro))
          and GetPathByRouter(m_NextIntro.router))
        SwapIntros();

      if (m_GotInboundTraffic and m_LastInboundTraffic + sendTimeout <= now)
      {
        // timeout on other side
        UpdateIntroSet();
        MarkCurrentIntroBad(now);
        ShiftIntroRouter(remoteIntro.router);
      }
      // check for stale intros
      // update the introset if we think we need to
      if (currentIntroSet.HasStaleIntros(now, path::intro_path_spread))
      {
        UpdateIntroSet();
      }
      // lookup router in intro if set and unknown
      if (not m_NextIntro.router.IsZero())
        m_Endpoint->EnsureRouterIsKnown(m_NextIntro.router);
      // expire bad intros
      auto itr = m_BadIntros.begin();
      while (itr != m_BadIntros.end())
      {
        if (now > itr->second && now - itr->second > path::default_lifetime)
          itr = m_BadIntros.erase(itr);
        else
          ++itr;
      }

      if (ReadyToSend() and not m_ReadyHooks.empty())
      {
        const auto path = GetPathByRouter(remoteIntro.router);
        if (not path)
        {
          LogWarn(Name(), " ready but no path to ", remoteIntro.router, " ???");
          return true;
        }
        for (const auto& hook : m_ReadyHooks)
          hook(this);
        m_ReadyHooks.clear();
      }

      const auto timeout = std::min(lastGoodSend, m_LastInboundTraffic);
      if (lastGoodSend > 0s and now >= timeout + (sendTimeout / 2))
      {
        // send a keep alive to keep this session alive
        KeepAlive();
      }
      // if we are dead return true so we are removed
      return timeout > 0s ? (now >= timeout && now - timeout > sendTimeout)
                          : (now >= createdAt && now - createdAt > connectTimeout);
    }

    void
    OutboundContext::AddReadyHook(std::function<void(OutboundContext*)> hook, llarp_time_t timeout)
    {
      if (ReadyToSend())
      {
        hook(this);
        return;
      }
      if (m_ReadyHooks.empty())
      {
        m_router->loop()->call_later(timeout, [this]() {
          LogWarn(Name(), " did not obtain session in time");
          for (const auto& hook : m_ReadyHooks)
            hook(nullptr);
          m_ReadyHooks.clear();
        });
      }
      m_ReadyHooks.push_back(hook);
    }

    std::optional<std::vector<RouterContact>>
    OutboundContext::GetHopsForBuild()
    {
      if (m_NextIntro.router.IsZero())
      {
        ShiftIntroduction(false);
      }
      if (m_NextIntro.router.IsZero())
        return std::nullopt;
      return GetHopsAlignedToForBuild(m_NextIntro.router, m_Endpoint->SnodeBlacklist());
    }

    bool
    OutboundContext::ShouldBuildMore(llarp_time_t now) const
    {
      if (markedBad or path::Builder::BuildCooldownHit(now))
        return false;
      if (NumInStatus(path::ePathBuilding) >= numDesiredPaths)
        return false;

      if (m_BadIntros.count(remoteIntro))
        return true;

      size_t numValidPaths = 0;
      ForEachPath([now, &numValidPaths](path::Path_ptr path) {
        if (not path->IsReady())
          return;
        if (not path->intro.ExpiresSoon(now, path::default_lifetime - path::intro_path_spread))
          numValidPaths++;
      });
      return numValidPaths < numDesiredPaths;
    }

    void
    OutboundContext::MarkCurrentIntroBad(llarp_time_t now)
    {
      MarkIntroBad(remoteIntro, now);
    }

    void
    OutboundContext::MarkIntroBad(const Introduction& intro, llarp_time_t now)
    {
      // insert bad intro
      m_BadIntros[intro] = now;
    }

    bool
    OutboundContext::IntroSent() const
    {
      return sentIntro;
    }

    bool
    OutboundContext::IntroGenerated() const
    {
      return sentIntro;
    }

    bool
    OutboundContext::ShiftIntroduction(bool rebuild)
    {
      bool success = false;
      const auto now = Now();
      if (abs(now - lastShift) < shiftTimeout)
        return false;
      bool shifted = false;
      std::vector<Introduction> intros = currentIntroSet.intros;
      if (intros.size() > 1)
      {
        std::shuffle(intros.begin(), intros.end(), CSRNG{});
      }

      // to find a intro on the same router as before that is newer
      for (const auto& intro : intros)
      {
        if (intro.ExpiresSoon(now))
          continue;
        if (m_Endpoint->SnodeBlacklist().count(intro.router))
          continue;
        if (m_BadIntros.find(intro) == m_BadIntros.end() && remoteIntro.router == intro.router)
        {
          if (intro.expiresAt > m_NextIntro.expiresAt)
          {
            success = true;
            m_NextIntro = intro;
            return true;
          }
        }
      }
      if (!success)
      {
        /// pick newer intro not on same router
        for (const auto& intro : intros)
        {
          if (m_Endpoint->SnodeBlacklist().count(intro.router))
            continue;
          m_Endpoint->EnsureRouterIsKnown(intro.router);
          if (intro.ExpiresSoon(now))
            continue;
          if (m_BadIntros.find(intro) == m_BadIntros.end() && m_NextIntro != intro)
          {
            if (intro.expiresAt > m_NextIntro.expiresAt)
            {
              shifted = intro.router != m_NextIntro.router;
              m_NextIntro = intro;
              success = true;
            }
          }
        }
      }
      if (m_NextIntro.router.IsZero())
        return false;
      if (shifted)
        lastShift = now;
      if (rebuild && !BuildCooldownHit(Now()))
        BuildOneAlignedTo(m_NextIntro.router);
      return success;
    }

    void
    OutboundContext::HandlePathDied(path::Path_ptr path)
    {
      // unconditionally update introset
      UpdateIntroSet();
      const RouterID endpoint{path->Endpoint()};
      // if a path to our current intro died...
      if (endpoint == remoteIntro.router)
      {
        // figure out how many paths to this router we have
        size_t num = 0;
        ForEachPath([&](const path::Path_ptr& p) {
          if (p->Endpoint() == endpoint && p->IsReady())
            ++num;
        });
        if (num == 0)
        {
          // we have no more paths to this endpoint so we want to pivot off of it
          MarkCurrentIntroBad(Now());
          ShiftIntroRouter(endpoint);
          if (m_NextIntro.router != endpoint)
            BuildOneAlignedTo(m_NextIntro.router);
        }
      }
    }

    bool
    OutboundContext::HandleHiddenServiceFrame(path::Path_ptr p, const ProtocolFrame& frame)
    {
      m_LastInboundTraffic = m_Endpoint->Now();
      m_GotInboundTraffic = true;
      if (frame.R)
      {
        // handle discard
        ServiceInfo si;
        if (!m_Endpoint->GetSenderFor(frame.T, si))
        {
          LogWarn("no sender for T=", frame.T);
          return false;
        }
        // verify source
        if (!frame.Verify(si))
        {
          LogWarn("signature verification failed, T=", frame.T);
          return false;
        }
        // remove convotag it doesn't exist
        LogWarn("remove convotag T=", frame.T, " R=", frame.R);

        AuthResult result{AuthResultCode::eAuthFailed, "unknown reason"};
        if (const auto maybe = AuthResultCodeFromInt(frame.R))
          result.code = *maybe;
        SharedSecret sessionKey{};
        if (m_DataHandler->GetCachedSessionKeyFor(frame.T, sessionKey))
        {
          ProtocolMessage msg{};
          if (frame.DecryptPayloadInto(sessionKey, msg))
          {
            if (msg.proto == ProtocolType::Auth and not msg.payload.empty())
            {
              result.reason = std::string{
                  reinterpret_cast<const char*>(msg.payload.data()), msg.payload.size()};
            }
          }
        }

        m_Endpoint->RemoveConvoTag(frame.T);
        if (authResultListener)
        {
          authResultListener(result);
          authResultListener = nullptr;
        }
        return true;
      }
      std::function<void(std::shared_ptr<ProtocolMessage>)> hook = nullptr;
      if (authResultListener)
      {
        std::function<void(AuthResult)> handler = authResultListener;
        authResultListener = nullptr;
        hook = [handler](std::shared_ptr<ProtocolMessage> msg) {
          AuthResult result{AuthResultCode::eAuthAccepted, "OK"};
          if (msg->proto == ProtocolType::Auth and not msg->payload.empty())
          {
            result.reason = std::string{
                reinterpret_cast<const char*>(msg->payload.data()), msg->payload.size()};
          }
          handler(result);
        };
      }
      const auto& ident = m_Endpoint->GetIdentity();
      if (not frame.AsyncDecryptAndVerify(m_Endpoint->Loop(), p, ident, m_Endpoint, hook))
      {
        // send reset convo tag message
        LogError("failed to decrypt and verify frame");
        ProtocolFrame f;
        f.R = 1;
        f.T = frame.T;
        f.F = p->intro.pathID;

        f.Sign(ident);
        {
          LogWarn("invalidating convotag T=", frame.T);
          m_Endpoint->RemoveConvoTag(frame.T);
          m_Endpoint->m_SendQueue.tryPushBack(
              SendEvent_t{std::make_shared<routing::PathTransferMessage>(f, frame.F), p});
        }
      }
      return true;
    }

    void
    OutboundContext::SendPacketToRemote(const llarp_buffer_t& buf, service::ProtocolType t)
    {
      AsyncEncryptAndSendTo(buf, t);
    }

  }  // namespace service

}  // namespace llarp
