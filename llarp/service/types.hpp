#pragma once

#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/thread/queue.hpp>

#include <deque>
#include <memory>
#include <queue>
#include <unordered_map>

/** TODO:
    - The commented functions are utilities for managing sessions to remote hidden services. They
   need to be redefined with the correct parameters and called from service::Handler, as
   service::Endpoint is for local hidden service management
   - ^^ Is this still true...?
*/

using namespace std::literals;

namespace llarp
{
    namespace session
    {
        struct OutboundSession;
    }
    namespace path
    {
        struct Path;
    }
    namespace routing
    {
        struct PathTransferMessage;
    }

    namespace service
    {
        // Supported protocol types; the values are given explicitly because they are specifically
        // used when sending over the wire.
        enum class ProtocolType : uint64_t
        {
            CONTROL = 0UL,
            IPV4 = 1UL,
            IPV6 = 2UL,
            EXIT = 3UL,
            AUTH = 4UL,
            TCP2QUIC = 5UL,
        };

        inline constexpr std::string_view to_string(ProtocolType t)
        {
            return t == ProtocolType::CONTROL ? "Control"sv
                : t == ProtocolType::IPV4     ? "TrafficV4"sv
                : t == ProtocolType::IPV6     ? "TrafficV6"sv
                : t == ProtocolType::EXIT     ? "Exit"sv
                : t == ProtocolType::AUTH     ? "Auth"sv
                : t == ProtocolType::TCP2QUIC ? "TCP->QUIC"sv
                                              : "(unknown-protocol-type)"sv;
        }

        // namespace util
        // {
        //     static void ExpireSNodeSessions(/* std::chrono::milliseconds now, SNodeConnectionMap& sessions */);

        //     static void DeregisterDeadSessions(/* std::chrono::milliseconds now, ConnectionMap& sessions */);

        //     static void TickRemoteSessions(
        //   /* std::chrono::milliseconds now,
        //   ConnectionMap& remoteSessions,
        //   ConnectionMap& deadSessions,
        //   std::unordered_map<SessionTag, Session>& sessions */);

        //     static void ExpireConvoSessions(
        //         /* std::chrono::milliseconds now, std::unordered_map<SessionTag, Session>& sessions */);

        //     static void StopRemoteSessions(/* ConnectionMap& remoteSessions */);

        //     static void StopSnodeSessions(/* SNodeConnectionMap& sessions */);

        //     static bool HasPathToService(
        //         /* const Address& addr, const ConnectionMap& remoteSessions */);

        //     static bool GetConvoTagsForService(
        //   /* const std::unordered_map<SessionTag, Session>& sessions,
        //   const Address& addr,
        //   std::set<SessionTag>& tags */);
        // }  // namespace util

        //     template <typename Endpoint_t>
        // static std::
        //     unordered_set<std::shared_ptr<path::Path>, path::Endpoint_Hash, path::endpoint_comparator>
        //     GetManyPathsWithUniqueEndpoints(
        //         /* Endpoint_t* ep,
        //         size_t N,
        //         std::optional<dht::Key_t> maybeLocation = std::nullopt,
        //         size_t tries = 10 */)
        //     {
        //         // std::unordered_set<RouterID> exclude;
        //         std::unordered_set<std::shared_ptr<path::Path>, path::Endpoint_Hash, path::endpoint_comparator>
        //         paths;
        //         // do
        //         // {
        //         //   --tries;
        //         //   std::shared_ptr<path::Path> path;
        //         //   if (maybeLocation)
        //         //   {
        //         //     path = ep->GetEstablishedPathClosestTo(RouterID{maybeLocation->as_array()},
        //         //     exclude);
        //         //   }
        //         //   else
        //         //   {
        //         //     path = ep->PickRandomEstablishedPath();
        //         //   }
        //         //   if (path and path->IsReady())
        //         //   {
        //         //     paths.emplace(path);
        //         //     exclude.insert(path->Endpoint());
        //         //   }
        //         // } while (tries > 0 and paths.size() < N);
        //         return paths;
        //     }
    }  // namespace service

}  // namespace llarp
