#pragma once

#include <llarp/address/address.hpp>
#include <llarp/address/ip_packet.hpp>
#include <llarp/constants/path.hpp>
#include <llarp/contact/tag.hpp>
#include <llarp/ev/tcp.hpp>
#include <llarp/path/path.hpp>

#include <oxen/quic.hpp>

#include <deque>
#include <queue>

namespace llarp
{
    using on_session_init_hook = std::function<void(ip_v)>;

    namespace link
    {
        class TunnelManager;
    }  //  namespace link

    namespace handlers
    {
        class SessionEndpoint;
    }  // namespace handlers

    /** Snode vs Client Session
        - client to client: shared secret (symmetric key) is negotiated
        - client to snode:
          - the traffic to the pivot is encrypted
          - the pivot is the terminus, so data doesn't need to be encrypted
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

            SessionTag _tag;
            NetworkAddress _remote;

            shared_kx_data session_keys{};

            // used for bridging data messages across aligned paths
            HopID _remote_pivot_txid;

            bool _use_tun;
            bool _is_outbound;

            const bool _is_exit_session{false};

            std::shared_ptr<path::Path> _current_path;
            HopID _pivot_txid;

            // manually routed QUIC endpoint
            std::shared_ptr<oxen::quic::Endpoint> _ep;

            std::shared_ptr<oxen::quic::connection_interface> _ci;

            // TCPHandle listeners mapped to the local port they are bound on
            std::unordered_map<uint16_t, std::shared_ptr<TCPHandle>> _handles;

            std::unordered_set<std::shared_ptr<TCPConnection>> _tcp_conns;

            void _init_ep();

            const std::shared_ptr<path::Path>& current_path() const { return _current_path; }

          public:
            BaseSession(
                Router& r,
                std::shared_ptr<path::Path> _p,
                handlers::SessionEndpoint& parent,
                NetworkAddress remote,
                HopID remote_pivot_txid,
                SessionTag _t,
                bool use_tun,
                bool is_outbound,
                std::optional<shared_kx_data> kx_data = std::nullopt);

            virtual ~BaseSession() = default;

            bool is_outbound() const { return _is_outbound; }

            const NetworkAddress& remote() const { return _remote; }

            NetworkAddress remote() { return _remote; }

            bool send_path_control_message(
                std::string method, std::string body, std::function<void(oxen::quic::message)> func);

            bool send_path_data_message(std::string data);

            void recv_path_data_message(bstring data);

            void set_new_current_path(std::shared_ptr<path::Path> _new_path);

            void tcp_backend_connect();

            void tcp_backend_listen(on_session_init_hook cb, uint16_t port = 0);

            bool using_tun() const { return _use_tun; }

            SessionTag tag() { return _tag; }

            const SessionTag& tag() const { return _tag; }

            bool is_exit_session() const { return _is_exit_session; }
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
                HopID remote_pivot_txid,
                SessionTag _t,
                std::optional<shared_kx_data> kx_data = std::nullopt);

            ~OutboundSession() override;

          private:
            const bool _is_snode_session{false};
            std::chrono::milliseconds _last_use;

          public:
            std::shared_ptr<path::PathHandler> get_self() override { return shared_from_this(); }

            std::weak_ptr<path::PathHandler> get_weak() override { return weak_from_this(); }

            std::shared_ptr<path::Path> current_path() { return _current_path; }

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

            const RouterID& remote_endpoint() const { return _remote.router_id(); }

            std::optional<HopID> current_pivot_txid() const
            {
                if (_pivot_txid.is_zero())
                    return std::nullopt;

                return _pivot_txid;
            }

            bool is_expired(std::chrono::milliseconds now) const;
        };

        struct InboundSession final : public BaseSession
        {
            InboundSession(
                NetworkAddress _remote,
                std::shared_ptr<path::Path> _path,
                handlers::SessionEndpoint& parent,
                HopID remote_pivot_txid,
                SessionTag _t,
                bool use_tun,
                std::optional<shared_kx_data> kx_data = std::nullopt);

            ~InboundSession() = default;

            void set_new_tag(const SessionTag& tag);
        };
    }  // namespace session

    namespace concepts
    {
        template <typename session_t>
        concept SessionType = std::is_base_of_v<llarp::session::BaseSession, session_t>;
    }  // namespace concepts
}  // namespace llarp