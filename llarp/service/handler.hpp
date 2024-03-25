#pragma once

#include <llarp/endpoint_base.hpp>
#include <llarp/handlers/remote.hpp>
#include <llarp/session/session.hpp>

#include <unordered_map>

namespace llarp
{
    struct Router;
}

namespace llarp::service
{
    /** Will handle all sessions to remote hidden services operated by either a
        client or a snode. This is NOT handling any thing related to clearnet
        exit nodes.
    */
    struct Handler final : /* public handlers::RemoteHandler, */ public std::enable_shared_from_this<Handler>
    {
        Handler(std::string name, Router& r);
        ~Handler();

        // std::shared_ptr<PathHandler> get_self()
        // {
        //     return shared_from_this();
        // }

        // std::weak_ptr<PathHandler> get_weak()
        // {
        //     return weak_from_this();
        // }

        StatusObject ExtractStatus() const;

        // bool should_hook_dns_msg(const dns::Message& msg) const;

        // bool handle_hooked_dns_msg(dns::Message msg, std::function<void(dns::Message)>);

        /// sets up networking and starts traffic
        bool Start();

        // bool HasLocalMappedAddrFor(const PubKey& pk) const;

        // huint128_t GetIPForIdent(const PubKey pk);

      private:
        void _configure();
        // huint128_t AllocateNewAddress();
        /// obtain ip for service node session, creates a new session if one does
        /// not existing already
        // huint128_t ObtainServiceNodeIP(const RouterID& router);

        // void MarkIPActive(huint128_t ip);

        // void KickIdentOffExit(const PubKey& pk);

        // bool should_init_tun;
        // std::shared_ptr<dns::Server> resolver;

        // std::unordered_map<PubKey, huint128_t> key_to_IP;

        // /// set of pubkeys we treat as snodes
        // std::set<PubKey> snode_keys;

        // std::unordered_map<huint128_t, PubKey> ip_to_key;

        // huint128_t _if_addr;
        // huint128_t highest_addr;

        // huint128_t next_addr;
        // IPRange ip_range;
        // std::string if_name;

        // std::unordered_map<huint128_t, std::chrono::milliseconds> ip_activity;

        // std::shared_ptr<vpn::NetworkInterface> if_net;

        // SockAddr resolver_addr;
        // std::vector<SockAddr> upstream_resolvers;

        // std::shared_ptr<link::TunnelManager> tunnel_manager;
    };
}  // namespace llarp::service
