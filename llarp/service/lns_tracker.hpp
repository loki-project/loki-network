#pragma once

#include "address.hpp"

#include <llarp/router_id.hpp>

#include <oxenc/variant.h>

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace llarp::service
{
    /// tracks and manages consensus of lns names we fetch from the network
    class LNSLookupTracker
    {
      public:
        using Addr_t = std::variant<Address, RouterID>;

      private:
        struct LookupInfo
        {
            std::unordered_set<Addr_t> m_CurrentValues;
            std::function<void(std::optional<Addr_t>)> m_HandleResult;
            std::size_t m_ResultsGotten = 0;
            std::size_t m_ResultsNeeded;

            LookupInfo(std::size_t wantResults, std::function<void(std::optional<Addr_t>)> resultHandler)
                : m_HandleResult{std::move(resultHandler)}, m_ResultsNeeded{wantResults}
            {}

            bool IsDone() const;

            void HandleOneResult(std::optional<Addr_t> result);
        };

        std::unordered_map<std::string, LookupInfo> m_PendingLookups;

      public:
        /// make a function that will handle consensus of an lns request
        /// name is the name we are requesting
        /// numPeers is the number of peers we asked
        /// resultHandler is a function that we are wrapping that will handle the final result
        std::function<void(std::optional<Addr_t>)> MakeResultHandler(
            std::string name, std::size_t numPeers, std::function<void(std::optional<Addr_t>)> resultHandler);
    };
}  // namespace llarp::service
