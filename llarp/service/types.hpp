#pragma once

// #include "protocol.hpp"
#include "session.hpp"

#include <llarp/path/path.hpp>
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
*/

namespace llarp
{
    // clang-format off
  namespace session { struct BaseSession; }
  namespace path { struct Path; }
  namespace routing { struct PathTransferMessage; }
    // clang-format on

    namespace service
    {
        // Supported protocol types; the values are given explicitly because they are specifically
        // used when sending over the wire.
        enum class ProtocolType : uint64_t
        {
            Control = 0UL,
            TrafficV4 = 1UL,
            TrafficV6 = 2UL,
            Exit = 3UL,
            Auth = 4UL,
            QUIC = 5UL,

        };

        inline constexpr std::string_view to_string(ProtocolType t)
        {
            using namespace std::literals;
            return t == ProtocolType::Control  ? "Control"sv
                : t == ProtocolType::TrafficV4 ? "TrafficV4"sv
                : t == ProtocolType::TrafficV6 ? "TrafficV6"sv
                : t == ProtocolType::Exit      ? "Exit"sv
                : t == ProtocolType::Auth      ? "Auth"sv
                : t == ProtocolType::QUIC      ? "QUIC"sv
                                               : "(unknown-protocol-type)"sv;
        }

        namespace util
        {
            static void ExpireSNodeSessions(/* llarp_time_t now, SNodeConnectionMap& sessions */);

            static void DeregisterDeadSessions(/* llarp_time_t now, ConnectionMap& sessions */);

            static void TickRemoteSessions(
          /* llarp_time_t now,
          ConnectionMap& remoteSessions,
          ConnectionMap& deadSessions,
          std::unordered_map<SessionTag, Session>& sessions */);

            static void ExpireConvoSessions(
                /* llarp_time_t now, std::unordered_map<SessionTag, Session>& sessions */);

            static void StopRemoteSessions(/* ConnectionMap& remoteSessions */);

            static void StopSnodeSessions(/* SNodeConnectionMap& sessions */);

            static bool HasPathToService(
                /* const Address& addr, const ConnectionMap& remoteSessions */);

            static bool GetConvoTagsForService(
          /* const std::unordered_map<SessionTag, Session>& sessions,
          const Address& addr,
          std::set<SessionTag>& tags */);
        }  // namespace util

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

    template <>
    inline constexpr bool IsToStringFormattable<service::ProtocolType> = true;
}  // namespace llarp
