#pragma once

#include "address.hpp"
#include "intro_set.hpp"
#include "lns_tracker.hpp"
#include "tag.hpp"
#include "types.hpp"

#include <llarp/router_id.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/decaying_hashtable.hpp>
#include <llarp/util/types.hpp>

#include <oxenc/variant.h>

#include <memory>
#include <queue>
#include <set>
#include <unordered_map>

namespace llarp::service
{
    struct EndpointState
    {
        std::set<RouterID> snode_blacklist;

        std::string key_file;
        std::string name;
        std::string net_NS;
        bool is_exit_enabled = false;

        // PendingTrafficMap pending_traffic;
        // ConnectionMap remote_sessions;
        // ConnectionMap dead_sessions;
        // std::set<SessionTag> inbound_convotags;
        // SNodeConnectionMap snode_sessions;
        // PendingRoutersMap pending_routers;

        std::chrono::milliseconds last_publish = 0s;
        std::chrono::milliseconds last_publish_attempt = 0s;
        /// our introset
        IntroSet local_introset;
        /// on initialize functions
        std::list<std::function<bool(void)>> on_init_callbacks;

        /// conversations
        std::unordered_map<SessionTag, Session> m_Sessions;

        llarp::util::DecayingHashTable<std::string, std::variant<Address, RouterID>, std::hash<std::string>> nameCache;

        LNSLookupTracker lnsTracker;

        StatusObject ExtractStatus(StatusObject& obj) const;
    };
}  // namespace llarp::service
