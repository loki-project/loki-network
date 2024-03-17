#pragma once

#include <llarp/address/ip_packet.hpp>
#include <llarp/auth/auth.hpp>
#include <llarp/constants/path.hpp>
#include <llarp/path/pathhandler.hpp>
#include <llarp/service/types.hpp>

#include <deque>
#include <queue>

namespace llarp
{
    class EndpointBase;
    struct Router;

    namespace link
    {
        class TunnelManager;
    }

    /** Snode vs Client Session
        - client to client: shared secret (symmetric key) is negotiated
        - client to snode:
          - the traffic to the pivot is encrypted
          - the pivot is the terminus, so data doesn't need to be encrypted
          - could set HopID to 0 to indicate
    */

    namespace session
    {
        struct BaseSession : public llarp::path::PathHandler, public std::enable_shared_from_this<BaseSession>
        {
            BaseSession(
                RouterID _router,
                Router& r,
                size_t hoplen,
                EndpointBase& parent,
                std::shared_ptr<auth::SessionAuthPolicy> a);

            ~BaseSession() override;

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

            bool is_path_dead(std::shared_ptr<path::Path> p, llarp_time_t dlt);

            void path_build_succeeded(const RouterID& remote, std::shared_ptr<path::Path> p) override;

            bool stop(bool send_close = false) override;

            void send_path_close(std::shared_ptr<path::Path> p);

            bool is_ready() const;

            const llarp::RouterID& Endpoint() const
            {
                return _remote_router;
            }

            std::optional<HopID> current_hop_id() const
            {
                if (_current_hop_id.is_zero())
                    return std::nullopt;

                return _current_hop_id;
            }

            bool is_expired(llarp_time_t now) const;

            bool send_path_control_message(
                std::string method, std::string body, std::function<void(std::string)> func = nullptr);

            bool send_path_data_message(std::string body);

            std::string name() const override
            {
                return prefix() + _remote_router.to_string();
            }

          protected:
            RouterID _remote_router;  // remote {service,exit} pubkey
            std::shared_ptr<auth::SessionAuthPolicy> _auth;

            virtual std::string prefix() const = 0;

          private:
            HopID _current_hop_id;

            // uint64_t _counter;
            llarp_time_t _last_use;

            // const bool _bundle_RC;
            const EndpointBase& _parent;
        };

        struct ExitSession final : public BaseSession
        {
            ExitSession(
                RouterID snodeRouter,
                Router& r,
                size_t hoplen,
                EndpointBase& parent,
                std::shared_ptr<auth::SessionAuthPolicy> a)
                : BaseSession{snodeRouter, r, hoplen, parent, a}
            {}

            ~ExitSession() override = default;

            std::string prefix() const override
            {
                return "exit::"s;
            }
        };

        struct ServiceSession final : public BaseSession
        {
            ServiceSession(
                const RouterID& _remote,
                Router& r,
                size_t hop_len,
                EndpointBase& parent,
                std::shared_ptr<auth::SessionAuthPolicy> a);

            ~ServiceSession() override = default;

            std::string prefix() const override
            {
                return _is_snode_service ? "snode::"s : "loki::"s;
            }

            const bool _is_snode_service{false};
        };

        struct InboundSession
        {
            InboundSession(Router& r, std::shared_ptr<path::Path> _path, RouterID _remote, EndpointBase& parent);

            ~InboundSession() = default;

            std::string name() const;

            std::shared_ptr<path::Path> current_path()
            {
                return _current_path;
            }

            void set_new_path(const std::shared_ptr<path::Path>& _new_path);

          protected:
            Router& _router;
            EndpointBase& _parent;

            RouterID _remote;

            std::shared_ptr<path::Path> _current_path;
        };

    }  // namespace session
}  // namespace llarp
