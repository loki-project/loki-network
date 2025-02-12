#pragma once

#include <llarp/address/address.hpp>
#include <llarp/constants/path.hpp>
#include <llarp/contact/tag.hpp>
#include <llarp/ev/tcp.hpp>
#include <llarp/net/ip_packet.hpp>
#include <llarp/path/path.hpp>

#include <oxen/quic.hpp>

#include <deque>
#include <queue>

namespace llarp
{
    using on_session_init_hook = std::function<void(ip_v)>;
    using recv_session_dgram_cb = std::function<void(std::vector<uint8_t>)>;

    inline constexpr size_t PATHS_PER_INTRO{2};

    namespace link
    {
        class TunnelManager;
    }  //  namespace link

    namespace handlers
    {
        class SessionEndpoint;
    }  // namespace handlers

    using intro_path_map = std::map<ClientIntro, path::PathPtrSet, ClientIntroComp>;

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

            session_tag _tag;
            NetworkAddress _remote;

            std::optional<shared_kx_data> session_keys{};

            // used for bridging data messages across aligned paths
            HopID _remote_pivot_txid;

            bool _use_tun;
            bool _is_outbound;
            bool _is_active{false};

            const bool _is_snode_session{false};
            const bool _is_exit_session{false};

            std::shared_ptr<path::Path> _current_path;
            HopID _pivot_txid;

            recv_session_dgram_cb _recv_dgram;

            // manually routed QUIC endpoint
            std::shared_ptr<oxen::quic::Endpoint> _ep;

            std::shared_ptr<oxen::quic::connection_interface> _ci;

            // TCPHandle listeners mapped to the local port they are bound on
            std::unordered_map<uint16_t, std::shared_ptr<TCPHandle>> _handles;

            std::unordered_set<std::shared_ptr<TCPConnection>> _tcp_conns;

            void _init_ep();

          public:
            BaseSession(
                Router& r,
                std::shared_ptr<path::Path> _p,
                handlers::SessionEndpoint& parent,
                NetworkAddress remote,
                HopID remote_pivot_txid,
                session_tag _t,
                bool use_tun,
                bool is_outbound,
                std::optional<shared_kx_data> kx_data = std::nullopt);

            virtual ~BaseSession() = default;

            bool is_outbound() const { return _is_outbound; }

            const std::shared_ptr<path::Path>& current_path() const { return _current_path; }

            const NetworkAddress& remote() const { return _remote; }

            NetworkAddress remote() { return _remote; }

            bool send_path_control_message(std::string method, std::string body, bt_control_response_hook func);

            bool send_path_data_message(std::string data);

            void recv_path_data_message(std::vector<uint8_t> data);

            void set_new_current_path(std::shared_ptr<path::Path> _new_path);

            void recv_path_switch2(HopID new_remote_txid, HopID new_local_txid);

            void recv_path_switch(HopID new_remote_txid);

            void publish_client_contact(const EncryptedClientContact& ecc, bt_control_response_hook func);

            void tcp_backend_connect();

            void tcp_backend_listen(on_session_init_hook cb, uint16_t port = 0);

            bool using_tun() const { return _use_tun; }

            session_tag tag() { return _tag; }

            const session_tag& tag() const { return _tag; }

            void set_new_tag(const session_tag& tag);

            bool is_exit_session() const { return _is_exit_session; }

            bool is_active() const { return _is_active; }

            void activate();

            void deactivate();

            virtual void send_path_close();

            virtual std::string to_string() const;

            static constexpr bool to_string_formattable = true;
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
                session_tag _t,
                intro_set cc,
                std::optional<shared_kx_data> kx_data = std::nullopt);

            ~OutboundSession() override;

          private:
            std::chrono::milliseconds _last_use;

            intro_path_map intro_path_mapping{};

            void populate_intro_map(intro_set& intros);

            void update_local_paths();

            void build_and_switch_paths();

            void map_path(const std::shared_ptr<path::Path>& p);

            void unmap_path(const std::shared_ptr<path::Path>& p);

          public:
            std::shared_ptr<path::PathHandler> get_self() override { return shared_from_this(); }

            std::weak_ptr<path::PathHandler> get_weak() override { return weak_from_this(); }

            void update_remote_intros(intro_set intros);

            void build_more(size_t n = 0) override;

            std::shared_ptr<path::Path> build1(std::vector<RemoteRC>& hops) override;

            nlohmann::json ExtractStatus() const;

            void path_died(std::shared_ptr<path::Path> p) override;

            void path_build_succeeded(std::shared_ptr<path::Path> p) override;

            void path_build_failed(std::shared_ptr<path::Path> p, bool timeout = false) override;

            void send_path_switch(std::shared_ptr<path::Path> _new_path);

            bool stop(bool send_close = false) override;

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
                session_tag _t,
                bool use_tun,
                std::optional<shared_kx_data> kx_data = std::nullopt);

            ~InboundSession() = default;
        };
    }  // namespace session

    namespace concepts
    {
        template <typename session_t>
        concept SessionType = std::is_base_of_v<llarp::session::BaseSession, session_t>;
    }  // namespace concepts
}  // namespace llarp
