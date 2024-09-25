#include "types.hpp"

#include <llarp/util/logging.hpp>

namespace llarp::service::util
{
    // void ExpireSNodeSessions(std::chrono::milliseconds now, SNodeConnectionMap& sessions)
    // {
    //   auto itr = sessions.begin();
    //   while (itr != sessions.end())
    //   {
    //     if (itr->second->ShouldRemove() && itr->second->IsStopped())
    //     {
    //       itr = sessions.erase(itr);
    //       continue;
    //     }
    //     // expunge next tick
    //     if (itr->second->IsExpired(now))
    //     {
    //       itr->second->Stop();
    //     }
    //     else
    //     {
    //       itr->second->Tick(now);
    //     }

    //     ++itr;
    //   }
    // }

    // void DeregisterDeadSessions(std::chrono::milliseconds now, ConnectionMap& sessions)
    // {
    //   auto itr = sessions.begin();
    //   while (itr != sessions.end())
    //   {
    //     if (itr->second->IsDone(now))
    //     {
    //       itr = sessions.erase(itr);
    //     }
    //     else
    //     {
    //       ++itr;
    //     }
    //   }
    // }

    // void TickRemoteSessions(
    //     std::chrono::milliseconds now,
    //     ConnectionMap& remoteSessions,
    //     ConnectionMap& deadSessions,
    //     std::unordered_map<SessionTag, Session>& sessions)
    // {
    //   auto itr = remoteSessions.begin();
    //   while (itr != remoteSessions.end())
    //   {
    //     itr->second->Tick(now);
    //     if (itr->second->Pump(now))
    //     {
    //       LogInfo(
    //           "marking session as dead T=",
    //           itr->second->get_current_tag(),
    //           " to ",
    //           itr->second->Addr());
    //       itr->second->Stop();
    //       sessions.erase(itr->second->get_current_tag());
    //       deadSessions.emplace(std::move(*itr));
    //       itr = remoteSessions.erase(itr);
    //     }
    //     else
    //     {
    //       ++itr;
    //     }
    //   }
    //   for (auto& item : deadSessions)
    //   {
    //     item.second->Tick(now);
    //   }
    // }

    // void ExpireConvoSessions(
    //     std::chrono::milliseconds now, std::unordered_map<SessionTag, Session>& sessions)
    // {
    //   auto itr = sessions.begin();
    //   while (itr != sessions.end())
    //   {
    //     if (itr->second.IsExpired(now))
    //     {
    //       LogInfo("Expire session T=", itr->first, " to ", itr->second.Addr());
    //       itr = sessions.erase(itr);
    //     }
    //     else
    //       ++itr;
    //   }
    // }

    // void StopRemoteSessions(ConnectionMap& remoteSessions)
    // {
    //   for (auto& item : remoteSessions)
    //   {
    //     item.second->Stop();
    //   }
    // }

    // void StopSnodeSessions(SNodeConnectionMap& sessions)
    // {
    //   for (auto& item : sessions)
    //   {
    //     item.second->Stop();
    //   }
    // }

    // bool HasPathToService(const Address& addr, const ConnectionMap& remoteSessions)
    // {
    //   auto range = remoteSessions.equal_range(addr);
    //   auto itr = range.first;
    //   while (itr != range.second)
    //   {
    //     if (itr->second->ReadyToSend())
    //       return true;
    //     ++itr;
    //   }
    //   return false;
    // }

    // bool GetConvoTagsForService(
    //     const std::unordered_map<SessionTag, Session>& sessions,
    //     const Address& info,
    //     std::set<SessionTag>& tags)
    // {
    //   bool inserted = false;
    //   auto itr = sessions.begin();
    //   while (itr != sessions.end())
    //   {
    //     if (itr->second.remote.Addr() == info)
    //     {
    //       if (tags.emplace(itr->first).second)
    //       {
    //         inserted = true;
    //       }
    //     }
    //     ++itr;
    //   }
    //   return inserted;
    // }
}  // namespace llarp::service::util
