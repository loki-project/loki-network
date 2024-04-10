#pragma once

#include <llarp/address/address.hpp>
#include <llarp/address/ip_packet.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/constants/path.hpp>
#include <llarp/path/path_handler.hpp>

#include <deque>
#include <queue>

namespace llarp
{
    struct Router;

    namespace link
    {
        class TunnelManager;
    }

    namespace handlers
    {
        struct LocalEndpoint;
        struct RemoteHandler;
    }  // namespace handlers

    /** Snode vs Client Session
        - client to client: shared secret (symmetric key) is negotiated
        - client to snode:
          - the traffic to the pivot is encrypted
          - the pivot is the terminus, so data doesn't need to be encrypted
          - could set HopID to 0 to indicate
    */

    namespace session
    {
        struct OutboundSession final : public llarp::path::PathHandler,
                                       public std::enable_shared_from_this<OutboundSession>
        {
          public:
            OutboundSession(
                RouterID _remote,
                handlers::RemoteHandler& parent,
                std::shared_ptr<path::Path> path,
                service::SessionTag _t,
                std::shared_ptr<auth::SessionAuthPolicy> a);

            ~OutboundSession() override;

          private:
            RouterID _remote_router;
            std::shared_ptr<auth::SessionAuthPolicy> _auth;

            std::string prefix() const
            {
                return _prefix;
            }

            std::shared_ptr<path::Path> _current_path;
            HopID _current_hop_id;

            service::SessionTag _tag;

            std::chrono::milliseconds _last_use;

            const handlers::RemoteHandler& _parent;

            const bool _is_exit_service{false};
            const bool _is_snode_service{false};
            const std::string _prefix{};

          public:
            std::shared_ptr<path::PathHandler> get_self() override
            {
                return shared_from_this();
            }

            std::weak_ptr<path::PathHandler> get_weak() override
            {
                return weak_from_this();
            }

            std::shared_ptr<path::Path> current_path()
            {
                if (auto itr = _paths.find(_remote_router); itr != _paths.end())
                    return itr->second;

                return nullptr;
            }

            void blacklist_snode(const RouterID& snode) override;

            void build_more(size_t n = 0) override;

            StatusObject ExtractStatus() const;

            void reset_path_state() override;

            void path_died(std::shared_ptr<path::Path> p) override;

            bool is_path_dead(std::shared_ptr<path::Path> p, std::chrono::milliseconds dlt);

            void path_build_succeeded(const RouterID& remote, std::shared_ptr<path::Path> p) override;

            bool stop(bool send_close = false) override;

            void send_path_close(std::shared_ptr<path::Path> p);

            bool is_ready() const;

            const llarp::RouterID& remote_endpoint() const
            {
                return _remote_router;
            }

            std::optional<HopID> current_hop_id() const
            {
                if (_current_hop_id.is_zero())
                    return std::nullopt;

                return _current_hop_id;
            }

            bool is_expired(std::chrono::milliseconds now) const;

            bool send_path_control_message(
                std::string method, std::string body, std::function<void(std::string)> func = nullptr);

            bool send_path_data_message(std::string body);

            std::string name() const override
            {
                return prefix().append(_remote_router.to_string());
            }

            service::SessionTag tag()
            {
                return _tag;
            }

            const service::SessionTag& tag() const
            {
                return _tag;
            }
        };

        struct InboundSession
        {
            InboundSession(
                Router& r,
                std::shared_ptr<path::Path> _path,
                NetworkAddress _remote,
                handlers::LocalEndpoint& parent,
                service::SessionTag _t,
                bool is_exit);

            ~InboundSession() = default;

            std::string name() const;

            const std::shared_ptr<path::Path>& current_path() const
            {
                return _current_path;
            }

            void set_new_path(const std::shared_ptr<path::Path>& _new_path);

            void set_new_tag(const service::SessionTag& tag);

          private:
            Router& _router;
            handlers::LocalEndpoint& _parent;

            service::SessionTag _tag;
            NetworkAddress _remote;

            std::shared_ptr<path::Path> _current_path;

            const bool _is_exit_service{false};
            const std::string _prefix{};
        };

        template <typename session_t>
        concept CONCEPT_COMPAT SessionType =
            std::is_same_v<OutboundSession, session_t> || std::is_same_v<InboundSession, session_t>;

    }  // namespace session
}  // namespace llarp
