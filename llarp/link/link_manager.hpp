#pragma once

#include "connection.hpp"

#include <llarp/address/address.hpp>
#include <llarp/constants/path.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/messages/common.hpp>
#include <llarp/path/transit_hop.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/decaying_hashset.hpp>
#include <llarp/util/logging.hpp>

#include <oxen/quic.hpp>
#include <oxen/quic/format.hpp>

#include <atomic>
#include <set>
#include <unordered_map>

namespace llarp
{
    struct LinkManager;
    class NodeDB;

    using conn_open_hook = oxen::quic::connection_established_callback;
    using conn_closed_hook = oxen::quic::connection_closed_callback;
    using stream_open_hook = oxen::quic::stream_open_callback;
    using stream_closed_hook = oxen::quic::stream_close_callback;

    using keep_alive = oxen::quic::opt::keep_alive;
    using inbound_alpns = oxen::quic::opt::inbound_alpns;
    using outbound_alpns = oxen::quic::opt::outbound_alpns;

    using static_secret = oxen::quic::opt::static_secret;

    inline const keep_alive RELAY_KEEP_ALIVE{10s};
    inline const keep_alive CLIENT_KEEP_ALIVE{10s};

    namespace alpns
    {
        inline const auto SN_ALPNS = "SERVICE_NODE"_us;
        inline const auto C_ALPNS = "CLIENT"_us;

        inline const inbound_alpns SERVICE_INBOUND{{SN_ALPNS, C_ALPNS}};
        inline const outbound_alpns SERVICE_OUTBOUND{{SN_ALPNS}};

        inline const inbound_alpns CLIENT_INBOUND{};
        inline const outbound_alpns CLIENT_OUTBOUND{{C_ALPNS}};
    }  // namespace alpns

    namespace link
    {
        struct Connection;

        struct Endpoint
        {
            Endpoint(std::shared_ptr<oxen::quic::Endpoint> ep, LinkManager& lm);

            std::shared_ptr<oxen::quic::Endpoint> endpoint;
            LinkManager& link_manager;

            /** Connection containers:
                - service_conns: holds all connections where the remote (from the perspective
                  of the local lokinet instance) is a service node. This means all relay to
                  relay connections are held here; clients will also hold their connections to
                  relays here as well
                - client_conns: holds all connections wehre the remote is a client. This is only
                  used by service nodes to store their client connections
            */
            std::unordered_map<RouterID, std::shared_ptr<link::Connection>> service_conns;
            std::unordered_map<RouterID, std::shared_ptr<link::Connection>> client_conns;

            std::shared_ptr<link::Connection> get_conn(const RouterID&) const;

            std::shared_ptr<link::Connection> get_service_conn(const RouterID&) const;

            bool have_conn(const RouterID& remote) const;

            bool have_client_conn(const RouterID& remote) const;

            bool have_service_conn(const RouterID& remote) const;

            std::tuple<size_t, size_t, size_t, size_t> connection_stats() const;

            size_t num_client_conns() const;

            size_t num_router_conns(bool active_only = true) const;

            template <typename... Opt>
            bool establish_connection(KeyedAddress remote, RouterID rid, Opt&&... opts);

            template <typename... Opt>
            bool establish_and_send(
                KeyedAddress remote,
                RouterID rid,
                std::optional<std::string> endpoint,
                std::string body,
                std::function<void(oxen::quic::message m)> func = nullptr,
                Opt&&... opts);

            void for_each_connection(std::function<void(const RouterID&, link::Connection&)> func);

            void close_connection(RouterID rid);

            void close_all();

          private:
            const bool _is_service_node;
        };
    }  // namespace link

    struct Router;

    struct LinkManager
    {
      public:
        static std::unique_ptr<LinkManager> make(Router& r);

        bool send_control_message(
            const RouterID& remote,
            std::string endpoint,
            std::string body,
            std::function<void(oxen::quic::message)> = nullptr);

        bool send_data_message(const RouterID& remote, std::string data);

        Router& router() const { return _router; }

      private:
        explicit LinkManager(Router& r);

        friend struct link::Endpoint;
        friend class NodeDB;

        // sessions to persist -> timestamp to end persist at
        std::unordered_map<RouterID, std::chrono::milliseconds> persisting_conns;

        util::DecayingHashSet<RouterID> clients{path::DEFAULT_LIFETIME};

        Router& _router;

        std::shared_ptr<NodeDB> node_db;

        std::shared_ptr<EventTicker> _gossip_ticker;

        oxen::quic::Address addr;

        const bool _is_service_node;

        // NOTE: DO NOT CHANGE THE ORDER OF THESE THREE OBJECTS
        // The quic Network must be created prior to the GNUTLS credentials, which are necessary for the creation of the
        // quic endpoint. These are delegate initialized in the LinkManager constructor sequentially
        std::unique_ptr<oxen::quic::Network> quic;
        std::shared_ptr<oxen::quic::GNUTLSCreds> tls_creds;
        std::shared_ptr<link::Endpoint> ep;

        std::atomic<bool> is_stopping;

        std::shared_ptr<oxen::quic::BTRequestStream> make_control(
            const std::shared_ptr<oxen::quic::connection_interface>& ci, const RouterID& rid);

        void on_inbound_conn(std::shared_ptr<oxen::quic::connection_interface> ci);

        void on_outbound_conn(RouterID id);

        void on_conn_open(oxen::quic::connection_interface& ci);

        void on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec);

        std::shared_ptr<oxen::quic::Endpoint> startup_endpoint();

        void register_commands(
            const std::shared_ptr<oxen::quic::BTRequestStream>& s, const RouterID& rid, bool client_only = false);

      public:
        void start_tickers();

        const oxen::quic::Address& local() { return addr; }

        void regenerate_and_gossip_rc();

        void gossip_rc(const RouterID& last_sender, const RemoteRC& rc);

        void handle_gossip_rc(oxen::quic::message m);

        void fetch_rcs(const RouterID& source, std::string payload, std::function<void(oxen::quic::message m)> func);

        void handle_fetch_rcs(oxen::quic::message m);

        void fetch_router_ids(
            const RouterID& via, std::string payload, std::function<void(oxen::quic::message m)> func);

        void handle_fetch_router_ids(oxen::quic::message m);

        void fetch_bootstrap_rcs(
            const RemoteRC& source, std::string payload, std::function<void(oxen::quic::message m)> func);

        void handle_fetch_bootstrap_rcs(oxen::quic::message m);

        bool have_connection_to(const RouterID& remote) const;

        bool have_service_connection_to(const RouterID& remote) const;

        bool have_client_connection_to(const RouterID& remote) const;

        void test_reachability(const RouterID& rid, conn_open_hook, conn_closed_hook);

        void connect_to(const RemoteRC& rc, conn_open_hook = nullptr, conn_closed_hook = nullptr);

        void connect_and_send(
            const RouterID& router,
            std::optional<std::string> endpoint,
            std::string body,
            std::function<void(oxen::quic::message m)> func = nullptr);

        void close_connection(RouterID rid);

        void stop();

        void close_all_links();

        void set_conn_persist(const RouterID& remote, std::chrono::milliseconds until);

        std::tuple<size_t, size_t, size_t, size_t> connection_stats() const;

        size_t get_num_connected_routers(bool active_only = true) const;

        size_t get_num_connected_clients() const;

        bool is_service_node() const;

        void check_persisting_conns(std::chrono::milliseconds now);

        nlohmann::json extract_status() const;

        std::set<RouterID> get_current_remotes() const;

        void for_each_connection(std::function<void(const RouterID&, link::Connection&)> func);

        // Attempts to connect to a number of random routers.
        //
        // This will try to connect to *up to* num_conns routers, but will not
        // check if we already have a connection to any of the random set, as making
        // that thread safe would be slow...I think.
        void connect_to_keep_alive(size_t num_conns);

        /// always maintain this many client connections to other routers
        int client_router_connections = 4;

      private:
        // TESTNET: // NEW CLIENT_CONTACT HANDLERS
        void handle_publish_cc(oxen::quic::message);
        void handle_find_cc(oxen::quic::message);
        void handle_resolve_sns(oxen::quic::message);

        // Inner handlers for relayed requests
        void _handle_path_control(oxen::quic::message, std::optional<std::string> = std::nullopt);
        void _handle_publish_cc(oxen::quic::message, std::optional<std::string> = std::nullopt);
        void _handle_find_cc(oxen::quic::message, std::optional<std::string> = std::nullopt);
        void _handle_resolve_sns(oxen::quic::message, std::optional<std::string> = std::nullopt);
        void _handle_initiate_session(oxen::quic::message, std::optional<std::string> = std::nullopt);
        void _handle_close_session(oxen::quic::message, std::optional<std::string> = std::nullopt);
        void _handle_path_switch(oxen::quic::message, std::optional<std::string> = std::nullopt);

        // Path messages
        void handle_path_build(oxen::quic::message, const RouterID& from);  // relay
        void handle_path_latency(oxen::quic::message);                      // relay
        void handle_path_transfer(oxen::quic::message);                     // relay

        // Sessions
        void handle_initiate_session(oxen::quic::message);
        void handle_close_session(oxen::quic::message);
        void handle_path_switch(oxen::quic::message);

        // These requests come over a path (as a "path_control" request),
        // we may or may not need to make a request to another relay,
        // then respond (onioned) back along the path.
        std::unordered_map<std::string_view, void (LinkManager::*)(oxen::quic::message, std::optional<std::string>)>
            path_requests = {
                {"path_control"sv, &LinkManager::_handle_path_control},
                {"publish_cc"sv, &LinkManager::_handle_publish_cc},
                {"find_cc"sv, &LinkManager::_handle_find_cc},
                {"resolve_sns"sv, &LinkManager::_handle_resolve_sns},
                {"session_init"sv, &LinkManager::_handle_initiate_session},
                {"session_close"sv, &LinkManager::_handle_close_session}};

        // Path relaying
        void handle_path_data_message(bstring dgram);
        void handle_path_control(oxen::quic::message);
        void handle_path_request(oxen::quic::message m, std::string payload);

        // Path responses
        void handle_path_latency_response(oxen::quic::message);
        void handle_path_transfer_response(oxen::quic::message);
    };

    namespace link
    {
        static auto logcat = log::Cat("link_manager");

        template <typename... Opt>
        bool Endpoint::establish_and_send(
            KeyedAddress remote,
            RouterID rid,
            std::optional<std::string> ep,
            std::string body,
            std::function<void(oxen::quic::message m)> func,
            Opt&&... opts)
        {
            return link_manager.router().loop()->call_get([&]() {
                try
                {
                    const auto& is_control = ep.has_value();
                    const auto us = _is_service_node ? "Relay"s : "Client"s;

                    log::debug(logcat, "Establishing connection to RID:{}", rid);
                    // add to service conns
                    auto [itr, b] = service_conns.try_emplace(rid, nullptr);

                    if (not b)
                    {
                        log::debug(logcat, "ERROR: attempting to establish an already-existing connection");
                        (is_control)
                            ? itr->second->control_stream->command(std::move(*ep), std::move(body), std::move(func))
                            : itr->second->conn->send_datagram(std::move(body));
                        return true;
                    }

                    auto conn_interface = endpoint->connect(
                        remote,
                        link_manager.tls_creds,
                        _is_service_node ? RELAY_KEEP_ALIVE : CLIENT_KEEP_ALIVE,
                        std::forward<Opt>(opts)...);

                    auto control_stream = conn_interface->template open_stream<oxen::quic::BTRequestStream>(
                        [](oxen::quic::Stream&, uint64_t error_code) {
                            log::warning(logcat, "BTRequestStream closed unexpectedly (ec:{})", error_code);
                        });

                    link_manager.register_commands(control_stream, rid, not _is_service_node);

                    log::debug(
                        logcat,
                        "{} dispatching {} on outbound connection to remote (rid:{})",
                        us,
                        is_control ? "control message (ep:{})"_format(*ep) : "data message",
                        rid);

                    (is_control) ? control_stream->command(std::move(*ep), std::move(body), std::move(func))
                                 : conn_interface->send_datagram(std::move(body));

                    itr->second =
                        std::make_shared<link::Connection>(std::move(conn_interface), std::move(control_stream));

                    log::info(logcat, "Outbound connection to RID:{} added to service conns...", rid);
                    return true;
                }
                catch (...)
                {
                    log::error(logcat, "Error: failed to establish connection to {}", remote);
                    return false;
                }
            });
        }

        template <typename... Opt>
        bool Endpoint::establish_connection(KeyedAddress remote, RouterID rid, Opt&&... opts)
        {
            return link_manager.router().loop()->call_get([&]() {
                try
                {
                    log::debug(logcat, "Establishing connection to RID:{}", rid);
                    // add to service conns
                    auto [itr, b] = service_conns.try_emplace(rid, nullptr);

                    if (not b)
                    {
                        log::debug(logcat, "ERROR: attempting to establish an already-existing connection");
                        return b;
                    }

                    auto conn_interface = endpoint->connect(
                        remote,
                        link_manager.tls_creds,
                        _is_service_node ? RELAY_KEEP_ALIVE : CLIENT_KEEP_ALIVE,
                        std::forward<Opt>(opts)...);

                    log::trace(logcat, "Created outbound connection with path: {}", conn_interface->path());

                    auto control_stream = conn_interface->template open_stream<oxen::quic::BTRequestStream>(
                        [](oxen::quic::Stream&, uint64_t error_code) {
                            log::warning(logcat, "BTRequestStream closed unexpectedly (ec:{})", error_code);
                        });

                    link_manager.register_commands(control_stream, rid, not _is_service_node);

                    itr->second =
                        std::make_shared<link::Connection>(std::move(conn_interface), std::move(control_stream));

                    log::info(logcat, "Outbound connection to RID:{} added to service conns...", rid);
                    return true;
                }
                catch (...)
                {
                    log::error(logcat, "Error: failed to establish connection to {}", remote);
                    return false;
                }
            });
        }
    }  // namespace link
}  // namespace llarp
