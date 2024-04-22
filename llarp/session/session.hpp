#pragma once

#include <llarp/address/address.hpp>
#include <llarp/address/ip_packet.hpp>
#include <llarp/constants/path.hpp>
#include <llarp/ev/tcp.hpp>
#include <llarp/path/path.hpp>
#include <llarp/service/tag.hpp>

#include <oxen/quic.hpp>

#include <deque>
#include <queue>

namespace llarp
{
    // struct Router;

    namespace link
    {
        class TunnelManager;
    }

    namespace handlers
    {
        class SessionEndpoint;
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
        /** Temporary base class for {Inbound,Outbound}Session objects to aggregate shared logic in relation
            to tunneled QUIC endpoints
        */
        struct BaseSession
        {
          protected:
            Router& _r;
            handlers::SessionEndpoint& _parent;

            service::SessionTag _tag;
            NetworkAddress _remote;

            bool _use_tun;
            bool _is_outbound;

            std::shared_ptr<path::Path> _current_path;
            HopID _current_hop_id;

            std::shared_ptr<oxen::quic::Endpoint> _ep;
            std::shared_ptr<oxen::quic::connection_interface> _ci;

            std::unordered_map<uint16_t, std::shared_ptr<TCPHandle>> _handles;

            std::unordered_set<std::shared_ptr<TCPConnection>> _tcp_conns;

            void _init_ep();

            const std::shared_ptr<path::Path>& current_path() const
            {
                return _current_path;
            }

          public:
            BaseSession(
                Router& r,
                std::shared_ptr<path::Path> _p,
                handlers::SessionEndpoint& parent,
                NetworkAddress remote,
                service::SessionTag _t,
                bool use_tun,
                bool is_outbound);

            constexpr bool is_outbound() const
            {
                return _is_outbound;
            }

            bool send_path_control_message(
                std::string method, std::string body, std::function<void(std::string)> func = nullptr);

            bool send_path_data_message(std::string data);

            void recv_path_data_message(bstring data);

            void set_new_current_path(std::shared_ptr<path::Path> _new_path);

            void tcp_backend_connect();

            void tcp_backend_listen(uint16_t port = 0);
        };

        struct OutboundSession final : public llarp::path::PathHandler,
                                       public BaseSession,
                                       public std::enable_shared_from_this<OutboundSession>
        {
          public:
            OutboundSession(
                NetworkAddress _remote,
                handlers::SessionEndpoint& parent,
                std::shared_ptr<path::Path> path,
                service::SessionTag _t,
                bool is_exit);

            ~OutboundSession() override;

          private:
            SecretKey _session_key;  // DISCUSS: is this useful?

            std::chrono::milliseconds _last_use;

            const bool _is_exit_service{false};
            const bool _is_snode_service{false};

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
                if (auto itr = _paths.find(_remote.router_id()); itr != _paths.end())
                    return itr->second;

                return nullptr;
            }

            void blacklist_snode(const RouterID& snode) override;

            void build_more(size_t n = 0) override;

            std::shared_ptr<path::Path> build1(std::vector<RemoteRC>& hops) override;

            nlohmann::json ExtractStatus() const;

            void reset_path_state() override;

            void path_died(std::shared_ptr<path::Path> p) override;

            bool is_path_dead(std::shared_ptr<path::Path> p, std::chrono::milliseconds dlt);

            void path_build_succeeded(std::shared_ptr<path::Path> p) override;

            bool stop(bool send_close = false) override;

            void send_path_close(std::shared_ptr<path::Path> p);

            bool is_ready() const;

            const RouterID& remote_endpoint() const
            {
                return _remote.router_id();
            }

            std::optional<HopID> current_hop_id() const
            {
                if (_current_hop_id.is_zero())
                    return std::nullopt;

                return _current_hop_id;
            }

            bool is_expired(std::chrono::milliseconds now) const;

            service::SessionTag tag()
            {
                return _tag;
            }

            const service::SessionTag& tag() const
            {
                return _tag;
            }
        };

        struct InboundSession final : public BaseSession
        {
            InboundSession(
                NetworkAddress _remote,
                std::shared_ptr<path::Path> _path,
                handlers::SessionEndpoint& parent,
                service::SessionTag _t,
                bool use_tun);

            ~InboundSession() = default;

            void set_new_tag(const service::SessionTag& tag);

          private:
            const bool _is_exit_node{false};  // TODO: remember why I added this here...
        };

        template <typename session_t>
        concept CONCEPT_COMPAT SessionType = std::is_base_of_v<BaseSession, session_t>;

    }  // namespace session
}  // namespace llarp
