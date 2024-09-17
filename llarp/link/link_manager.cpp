#include "link_manager.hpp"

#include "connection.hpp"
#include "contacts.hpp"

#include <llarp/messages/dht.hpp>
#include <llarp/messages/exit.hpp>
#include <llarp/messages/fetch.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/messages/session.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path.hpp>
#include <llarp/router/router.hpp>
#include <llarp/router_id.hpp>

#include <oxenc/bt_producer.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <algorithm>
#include <exception>
#include <set>

namespace llarp
{
    static auto logcat = llarp::log::Cat("lquic");

    static constexpr auto static_shared_key = "Lokinet static shared secret key"_usv;

    static static_secret make_static_secret(const SecretKey& sk)
    {
        ustring secret;
        secret.resize(32);

        crypto_generichash_blake2b_state st;
        crypto_generichash_blake2b_init(&st, static_shared_key.data(), static_shared_key.size(), secret.size());
        crypto_generichash_blake2b_update(&st, sk.data(), sk.size());
        crypto_generichash_blake2b_final(&st, reinterpret_cast<unsigned char*>(secret.data()), secret.size());

        return static_secret{std::move(secret)};
    }

    namespace link
    {
        Endpoint::Endpoint(std::shared_ptr<oxen::quic::Endpoint> ep, LinkManager& lm)
            : endpoint{std::move(ep)}, link_manager{lm}, _is_service_node{link_manager.is_service_node()}
        {}

        std::shared_ptr<link::Connection> Endpoint::get_service_conn(const RouterID& remote) const
        {
            return link_manager.router().loop()->call_get([this, rid = remote]() -> std::shared_ptr<link::Connection> {
                if (auto itr = service_conns.find(rid); itr != service_conns.end())
                    return itr->second;

                return nullptr;
            });
        }

        std::shared_ptr<link::Connection> Endpoint::get_conn(const RouterID& remote) const
        {
            return link_manager.router().loop()->call_get([this, rid = remote]() -> std::shared_ptr<link::Connection> {
                if (auto itr = service_conns.find(rid); itr != service_conns.end())
                    return itr->second;

                if (_is_service_node)
                {
                    if (auto itr = client_conns.find(rid); itr != client_conns.end())
                        return itr->second;
                }

                return nullptr;
            });

            return nullptr;
        }

        bool Endpoint::have_conn(const RouterID& remote) const
        {
            return have_service_conn(remote) or have_client_conn(remote);
        }

        bool Endpoint::have_client_conn(const RouterID& remote) const
        {
            return link_manager.router().loop()->call_get([this, remote]() { return client_conns.count(remote); });
        }

        bool Endpoint::have_service_conn(const RouterID& remote) const
        {
            return link_manager.router().loop()->call_get([this, remote]() { return service_conns.count(remote); });
        }

        void Endpoint::for_each_connection(std::function<void(link::Connection&)> hook)
        {
            link_manager.router().loop()->call([this, func = std::move(hook)]() {
                for (const auto& [rid, conn] : service_conns)
                    func(*conn);

                if (_is_service_node)
                {
                    for (const auto& [rid, conn] : client_conns)
                        func(*conn);
                }
            });
        }

        void Endpoint::close_connection(RouterID _rid)
        {
            link_manager._router.loop()->call([this, rid = _rid]() {
                if (auto itr = service_conns.find(rid); itr != service_conns.end())
                {
                    log::critical(logcat, "Closing connection to relay RID:{}", rid);
                    auto& conn = *itr->second->conn;
                    conn.close_connection();
                }
                else if (_is_service_node)
                {
                    if (auto itr = client_conns.find(rid); itr != client_conns.end())
                    {
                        log::critical(logcat, "Closing connection to client RID:{}", rid);
                        auto& conn = *itr->second->conn;
                        conn.close_connection();
                    }
                }
                else
                    log::critical(logcat, "Could not find connection to RID:{} to close!", rid);
            });
        }

        void Endpoint::close_all()
        {
            for (auto& conn : service_conns)
                conn.second->close_quietly();

            service_conns.clear();

            for (auto& conn : client_conns)
                conn.second->close_quietly();

            client_conns.clear();
        }

        std::tuple<size_t, size_t, size_t, size_t> Endpoint::connection_stats() const
        {
            return link_manager.router().loop()->call_get([this]() -> std::tuple<size_t, size_t, size_t, size_t> {
                size_t in{0}, out{0};

                for (const auto& c : service_conns)
                {
                    if (c.second->is_inbound())
                        ++in;
                    else
                        ++out;
                }

                for (const auto& c : client_conns)
                {
                    if (c.second->is_inbound())
                        ++in;
                    else
                        ++out;
                }

                return {in, out, service_conns.size(), client_conns.size()};
            });
        }

        size_t Endpoint::num_client_conns() const
        {
            return link_manager.router().loop()->call_get([this]() { return client_conns.size(); });
        }

        size_t Endpoint::num_router_conns() const
        {
            return link_manager.router().loop()->call_get([this]() { return service_conns.size(); });
        }
    }  // namespace link

    std::tuple<size_t, size_t, size_t, size_t> LinkManager::connection_stats() const
    {
        return ep->connection_stats();
    }

    size_t LinkManager::get_num_connected_routers() const
    {
        return ep->num_router_conns();
    }

    size_t LinkManager::get_num_connected_clients() const
    {
        return ep->num_client_conns();
    }

    using messages::serialize_response;

    void LinkManager::for_each_connection(std::function<void(link::Connection&)> func)
    {
        if (is_stopping)
            return;

        return ep->for_each_connection(func);
    }

    void LinkManager::register_commands(
        const std::shared_ptr<oxen::quic::BTRequestStream>& s, const RouterID& remote_rid, bool client_only)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        s->register_handler("path_control"s, [this, rid = remote_rid](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_path_control(std::move(msg), rid); });
        });

        if (client_only)
        {
            s->register_handler("session_init", [this](oxen::quic::message m) mutable {
                _router.loop()->call([&, msg = std::move(m)]() mutable { handle_initiate_session(std::move(msg)); });
            });
            log::debug(logcat, "Registered all client-only BTStream commands!");
            return;
        }

        s->register_handler("path_build"s, [this, rid = remote_rid](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_path_build(std::move(msg), rid); });
        });

        s->register_handler("bfetch_rcs"s, [this](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_fetch_bootstrap_rcs(std::move(msg)); });
        });

        s->register_handler("fetch_rcs"s, [this](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_fetch_rcs(std::move(msg)); });
        });

        s->register_handler("fetch_rids"s, [this](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_fetch_router_ids(std::move(msg)); });
        });

        s->register_handler("gossip_rc"s, [this](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_gossip_rc(std::move(msg)); });
        });

        for (auto& method : path_requests)
        {
            s->register_handler(
                std::string{method.first}, [this, func = std::move(method.second)](oxen::quic::message m) mutable {
                    _router.loop()->call([&, msg = std::move(m), func = std::move(func)]() mutable {
                        auto body = msg.body_str();
                        auto respond = [&, m = std::move(msg)](std::string response) mutable {
                            m.respond(std::move(response), m.is_error());
                        };
                        std::invoke(func, this, body, std::move(respond));
                    });
                });
        }

        log::debug(logcat, "Registered all commands for connection to remote RID:{}", remote_rid);
    }

    void LinkManager::start_tickers()
    {
        log::debug(logcat, "Starting gossip ticker...");
        _gossip_ticker = _router.loop()->call_every(
            _router._gossip_interval,
            [this]() {
                log::critical(logcat, "Regenerating and gossiping RC...");
                _router.router_contact.resign();
                _router.save_rc();
                gossip_rc(_router.local_rid(), _router.router_contact.to_remote());
            },
            true);
    }

    LinkManager::LinkManager(Router& r)
        : _router{r},
          node_db{_router.node_db()},
          _is_service_node{_router.is_service_node()},
          quic{std::make_unique<oxen::quic::Network>()},
          tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_keys(
              {reinterpret_cast<const char*>(_router.identity().data()), 32},
              {reinterpret_cast<const char*>(_router.router_id().data()), 32})},
          ep{_router.loop()->template make_shared<link::Endpoint>(startup_endpoint(), *this)},
          is_stopping{false}
    {}

    std::unique_ptr<LinkManager> LinkManager::make(Router& r)
    {
        std::unique_ptr<LinkManager> ptr{new LinkManager(r)};
        return ptr;
    }

    std::shared_ptr<oxen::quic::Endpoint> LinkManager::startup_endpoint()
    {
        /** Parameters:
              - local bind address
              - conection open callback
              - connection close callback
              - stream constructor callback
                - will return a BTRequestStream on the first call to get_new_stream<BTRequestStream>
                - bt stream construction contains a stream close callback that shuts down the
           connection if the btstream closes unexpectedly
        */
        auto e = quic->endpoint(
            _router.listen_addr(),
            make_static_secret(_router.identity()),
            [this](oxen::quic::connection_interface& ci) { return on_conn_open(ci); },
            [this](oxen::quic::connection_interface& ci, uint64_t ec) { return on_conn_closed(ci, ec); },
            [this](oxen::quic::dgram_interface&, bstring dgram) { handle_path_data_message(std::move(dgram)); },
            is_service_node() ? alpns::SERVICE_INBOUND : alpns::CLIENT_INBOUND,
            is_service_node() ? alpns::SERVICE_OUTBOUND : alpns::CLIENT_OUTBOUND,
            oxen::quic::opt::disable_stateless_reset{});

        // While only service nodes accept inbound connections, clients must have this key verify
        // callback set. It will reject any attempted inbound connection to a lokinet client prior
        // to handshake completion
        tls_creds->set_key_verify_callback([this](const ustring_view& key, const ustring_view& alpn) {
            return _router.loop()->call_get([&]() {
                RouterID other{key.data()};
                auto us = router().is_bootstrap_seed() ? "Bootstrap seed node"s : "Service node"s;
                auto is_snode = is_service_node();

                if (is_snode)
                {
                    if (alpn == alpns::C_ALPNS)
                    {
                        log::critical(logcat, "{} node accepting client connection (remote ID:{})!", us, other);
                        ep->client_conns.emplace(other, nullptr);
                        return true;
                    }

                    if (alpn == alpns::SN_ALPNS)
                    {
                        // verify as service node!
                        bool result = node_db->registered_routers().count(other);
                        // result = true;  // TESTNET: turn this off for non-local testing

                        if (result)
                        {
                            auto [itr, b] = ep->service_conns.try_emplace(other, nullptr);

                            if (not b)
                            {
                                // If we fail to try_emplace a connection to the incoming RID, then
                                // we are simultaneously dealing with an outbound and inbound from
                                // the same connection. To resolve this, both endpoints will defer
                                // to the connection initiated by the RID that appears first in
                                // lexicographical order
                                auto defer_to_incoming = other < router().local_rid();

                                if (defer_to_incoming)
                                {
                                    itr->second->conn->set_close_quietly();
                                    itr->second = nullptr;
                                }

                                log::critical(
                                    logcat,
                                    "{} node received inbound with ongoing outbound to remote "
                                    "(RID:{}); {}!",
                                    us,
                                    other,
                                    defer_to_incoming ? "deferring to inbound" : "rejecting in favor of outbound");

                                return defer_to_incoming;
                            }

                            log::critical(
                                logcat, "{} node accepting inbound from registered remote (RID:{})", us, other);
                        }
                        else
                            log::critical(
                                logcat,
                                "{} node was unable to confirm remote (RID:{}) is registered; "
                                "rejecting "
                                "connection!",
                                us,
                                other);

                        return result;
                    }

                    log::critical(logcat, "{} node received unknown ALPN; rejecting connection!", us);
                    return false;
                }

                // TESTNET: change this to an error message later; just because someone tries to
                // erroneously connect to a local lokinet client doesn't mean we should kill the
                // program?
                throw std::runtime_error{"Clients should not be validating inbound connections!"};
            });
        });

        if (_router.is_service_node())
            e->listen(tls_creds);

        return e;
    }

    std::shared_ptr<oxen::quic::BTRequestStream> LinkManager::make_control(
        oxen::quic::connection_interface& ci, const RouterID& remote)
    {
        auto control_stream = ci.template queue_incoming_stream<oxen::quic::BTRequestStream>(
            [](oxen::quic::Stream&, uint64_t error_code) {
                log::warning(logcat, "BTRequestStream closed unexpectedly (ec:{})", error_code);
            });

        log::critical(logcat, "Queued BTStream to be opened (ID:{})", control_stream->stream_id());
        assert(control_stream->stream_id() == 0);
        register_commands(control_stream, remote, not _is_service_node);

        return control_stream;
    }

    void LinkManager::on_inbound_conn(oxen::quic::connection_interface& ci)
    {
        assert(_is_service_node);
        RouterID rid{ci.remote_key()};

        auto control = make_control(ci, rid);

        _router.loop()->call([&, ci_ptr = ci.shared_from_this(), bstream = std::move(control), rid]() {
            bool is_client_conn = false;
            if (auto it = ep->service_conns.find(rid); it != ep->service_conns.end())
            {
                log::debug(logcat, "Configuring inbound connection from relay RID:{}", rid);
                it->second = std::make_shared<link::Connection>(std::move(ci_ptr), std::move(bstream));
            }
            else if (auto it = ep->client_conns.find(rid); it != ep->client_conns.end())
            {
                is_client_conn = true;
                log::debug(logcat, "Configuring inbound connection from client RID:{}", rid.to_network_address(false));
                it->second = std::make_shared<link::Connection>(std::move(ci_ptr), std::move(bstream), false);
            }

            log::critical(
                logcat,
                "SERVICE NODE (RID:{}) ESTABLISHED CONNECTION TO RID:{}",
                _router.local_rid(),
                rid.to_network_address(!is_client_conn));
        });
    }

    void LinkManager::on_outbound_conn(oxen::quic::connection_interface& ci)
    {
        RouterID rid{ci.remote_key()};
        log::trace(logcat, "Outbound connection to {}", rid);

        if (ep->have_service_conn(rid))
        {
            log::debug(logcat, "Fetched configured outbound connection to relay RID:{}", rid);
        }

        log::critical(
            logcat,
            "{} (RID:{}) ESTABLISHED CONNECTION TO RID:{}",
            _is_service_node ? "SERVICE NODE" : "CLIENT",
            _router.local_rid().to_network_address(_is_service_node),
            rid);
    }

    void LinkManager::on_conn_open(oxen::quic::connection_interface& ci)
    {
        if (ci.is_inbound())
        {
            on_inbound_conn(ci);
        }
        else
        {
            on_outbound_conn(ci);
        }
    }

    void LinkManager::on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec)
    {
        _router.loop()->call(
            [this, ref_id = ci.reference_id(), rid = RouterID{ci.remote_key()}, error_code = ec, path = ci.path()]() {
                log::critical(logcat, "Purging quic connection {} (ec:{}) path:{}", ref_id, error_code, path);

                if (auto s_itr = ep->service_conns.find(rid); s_itr != ep->service_conns.end())
                {
                    log::critical(logcat, "Quic connection to relay RID:{} purged successfully", rid);
                    ep->service_conns.erase(s_itr);
                }
                else if (auto c_itr = ep->client_conns.find(rid); c_itr != ep->client_conns.end())
                {
                    log::critical(logcat, "Quic connection to client RID:{} purged successfully", rid);
                    ep->client_conns.erase(c_itr);
                }
                else
                    log::critical(logcat, "Nothing to purge for quic connection {}", ref_id);
            });
    }

    bool LinkManager::send_control_message(
        const RouterID& remote, std::string endpoint, std::string body, std::function<void(oxen::quic::message m)> func)
    {
        if (is_stopping)
            return false;

        if (func)
        {
            func = [this, f = std::move(func)](oxen::quic::message m) mutable {
                _router.loop()->call([func = std::move(f), msg = std::move(m)]() mutable { func(std::move(msg)); });
            };
        }

        if (auto conn = ep->get_conn(remote); conn)
        {
            conn->control_stream->command(std::move(endpoint), std::move(body), std::move(func));
            return true;
        }

        log::critical(logcat, "Queueing control message to {}", remote);

        _router.loop()->call(
            [this, rid = remote, endpoint = std::move(endpoint), body = std::move(body), f = std::move(func)]() {
                connect_and_send(std::move(rid), std::move(endpoint), std::move(body), std::move(f));
            });

        return false;
    }

    bool LinkManager::send_data_message(const RouterID& remote, std::string body)
    {
        if (is_stopping)
            return false;

        if (auto conn = ep->get_conn(remote); conn)
        {
            conn->conn->send_datagram(std::move(body));
            return true;
        }

        log::critical(logcat, "Queueing data message to {}", remote);

        _router.loop()->call([this, body = std::move(body), rid = remote]() {
            connect_and_send(std::move(rid), std::nullopt, std::move(body));
        });

        return false;
    }

    void LinkManager::close_connection(RouterID rid)
    {
        return ep->close_connection(rid);
    }

    void LinkManager::test_reachability(const RouterID& rid, conn_open_hook on_open, conn_closed_hook on_close)
    {
        if (auto rc = node_db->get_rc(rid))
        {
            connect_to(*rc, std::move(on_open), std::move(on_close));
        }
        else
            log::warning(logcat, "Could not find RouterContact for connection to rid:{}", rid);
    }

    void LinkManager::connect_and_send(
        const RouterID& router,
        std::optional<std::string> endpoint,
        std::string body,
        std::function<void(oxen::quic::message m)> func)
    {
        // by the time we have called this, we have already checked if we have a connection to this
        // RID in ::send_control_message_impl, at which point we will dispatch on that stream
        if (auto rc = node_db->get_rc(router))
        {
            const auto& remote_addr = rc->addr();

            if (auto rv = ep->establish_and_send(
                    KeyedAddress{router.to_view(), remote_addr},
                    *rc,
                    std::move(endpoint),
                    std::move(body),
                    std::move(func));
                rv)
            {
                log::info(logcat, "Begun establishing connection to {}", remote_addr);
                return;
            }

            log::warning(logcat, "Failed to begin establishing connection to {}", remote_addr);
        }
        else
            log::error(logcat, "Error: Could not find RC for connection to rid:{}, message not sent!", router);
    }

    void LinkManager::connect_to(const RemoteRC& rc, conn_open_hook on_open, conn_closed_hook on_close)
    {
        auto rid = rc.router_id();

        if (ep->have_service_conn(rid))
        {
            log::warning(logcat, "We already have a connection to {}!", rid);
            // TODO: should implement some connection failed logic, but not the same logic that
            // would be executed for another failure case
            return;
        }

        auto remote_addr = rc.addr();

        if (auto rv = ep->establish_connection(
                KeyedAddress{rid.to_view(), remote_addr}, rc, std::move(on_open), std::move(on_close));
            rv)
        {
            log::info(logcat, "Begun establishing connection to {}", remote_addr);
            return;
        }
        log::warning(logcat, "Failed to begin establishing connection to {}", remote_addr);
    }

    bool LinkManager::have_connection_to(const RouterID& remote) const
    {
        return ep->have_conn(remote);
    }

    bool LinkManager::have_service_connection_to(const RouterID& remote) const
    {
        return ep->have_service_conn(remote);
    }

    bool LinkManager::have_client_connection_to(const RouterID& remote) const
    {
        return ep->have_client_conn(remote);
    }

    void LinkManager::close_all_links()
    {
        log::info(logcat, "Closing all connections...");

        std::promise<void> p;
        auto f = p.get_future();

        _router.loop()->call([&]() mutable {
            ep->close_all();
            p.set_value();
        });

        f.get();

        ep.reset();
        log::info(logcat, "All connections closed!");
    }

    // TODO: put this in ~LinkManager() after sorting out close sequence and logic
    void LinkManager::stop()
    {
        if (is_stopping)
        {
            return;
        }

        log::info(logcat, "stopping loop");
        is_stopping = true;
        quic->set_shutdown_immediate();
        quic.reset();
        // ep.reset();
    }

    void LinkManager::set_conn_persist(const RouterID& remote, std::chrono::milliseconds until)
    {
        if (is_stopping)
            return;

        persisting_conns[remote] = std::max(until, persisting_conns[remote]);

        if (have_client_connection_to(remote))
        {
            // mark this as a client so we don't try to back connect
            clients.Upsert(remote);
        }
    }

    bool LinkManager::is_service_node() const
    {
        return _is_service_node;
    }

    // TODO: this?  perhaps no longer necessary in the same way?
    void LinkManager::check_persisting_conns(std::chrono::milliseconds)
    {
        if (is_stopping)
            return;
    }

    // TODO: this
    nlohmann::json LinkManager::extract_status() const
    {
        return {};
    }

    void LinkManager::connect_to_random(size_t num_conns, bool client_only)
    {
        auto filter = [this, client_only](const RemoteRC& rc) -> bool {
            const auto& rid = rc.router_id();
            auto res = client_only ? not ep->have_client_conn(rid) : not ep->have_conn(rid);

            log::trace(logcat, "RID:{} {}", rid, res ? "ACCEPTED" : "REJECTED");

            return res;
        };

        if (auto maybe = node_db->get_n_random_rcs_conditional(num_conns, filter))
        {
            std::vector<RemoteRC>& rcs = *maybe;

            for (const auto& rc : rcs)
                connect_to(rc);
        }
        else
            log::warning(logcat, "NodeDB query for {} random RCs for connection returned none", num_conns);
    }

    void LinkManager::handle_path_data_message(bstring message)
    {
        ustring nonce, hop_id_str, payload;

        try
        {
            oxenc::bt_dict_consumer btdc{message};
            std::tie(hop_id_str, nonce, payload) = Onion::deserialize(btdc);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        auto symmnonce = SymmNonce{nonce.data()};
        HopID hopid{hop_id_str.data()};
        auto hop = _router.path_context()->get_transit_hop(hopid);

        if (not hop)
            return;

        symmnonce = crypto::onion(payload.data(), payload.size(), hop->shared, symmnonce, hop->nonceXOR);

        // if terminal hop, pass to the correct path expecting to receive this message
        if (hop->terminal_hop)
        {
            NetworkAddress sender;
            bstring data;

            try
            {
                oxenc::bt_dict_consumer btdc{payload};
                std::tie(sender, data) = PathData::deserialize(btdc);

                if (auto session = _router.session_endpoint()->get_session(sender))
                {
                    session->recv_path_data_message(std::move(data));
                }
                else
                {
                    log::warning(logcat, "Could not find session (remote:{}) to relay path data message!", sender);
                }
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception: {}", e.what());
            }
        }
        else
        {
            // if not terminal hop, relay datagram onwards
            auto hop_is_rx = hop->rxid() == hopid;

            const auto& next_id = hop_is_rx ? hop->txid() : hop->rxid();
            const auto& next_router = hop_is_rx ? hop->upstream() : hop->downstream();

            std::string new_payload = Onion::serialize(symmnonce, next_id, payload);

            send_data_message(next_router, std::move(new_payload));
        }
    }

    void LinkManager::gossip_rc(const RouterID& last_sender, const RemoteRC& rc)
    {
        _router.loop()->call([this, last_sender, rc]() {
            int count = 0;
            const auto& gossip_src = rc.router_id();

            for (auto& [rid, conn] : ep->service_conns)
            {
                // don't send back to the gossip source or the last sender
                if (rid == gossip_src or rid == last_sender)
                    continue;

                send_control_message(
                    rid, "gossip_rc"s, GossipRCMessage::serialize(last_sender, rc), [](oxen::quic::message) {
                        log::trace(logcat, "PLACEHOLDER FOR GOSSIP RC RESPONSE HANDLER");
                    });
                ++count;
            }

            log::critical(logcat, "Dispatched {} GossipRC requests!", count);
        });
    }

    void LinkManager::handle_gossip_rc(oxen::quic::message m)
    {
        log::debug(logcat, "Handling GossipRC request...");

        // RemoteRC constructor wraps deserialization in a try/catch
        RemoteRC rc;
        RouterID src;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};

            btdc.required("rc");
            rc = RemoteRC{btdc.consume_dict_data()};
            src.from_relay_address(btdc.require<std::string>("sender"));
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "Exception handling GossipRC request: {}", e.what());
            return;
        }

        if (node_db->verify_store_gossip_rc(rc))
        {
            log::critical(logcat, "Received updated RC, forwarding to relay peers.");
            gossip_rc(_router.local_rid(), rc);
        }
        else
            log::debug(logcat, "Received known or old RC, not storing or forwarding.");
    }

    // TODO: can probably use ::send_control_message instead. Need to discuss the potential
    // difference in calling Endpoint::get_service_conn vs Endpoint::get_conn
    void LinkManager::fetch_bootstrap_rcs(
        const RemoteRC& source, std::string payload, std::function<void(oxen::quic::message m)> func)
    {
        func = [this, f = std::move(func)](oxen::quic::message m) mutable {
            _router.loop()->call([func = std::move(f), msg = std::move(m)]() mutable { func(std::move(msg)); });
        };

        const auto& rid = source.router_id();

        if (auto conn = ep->get_service_conn(rid); conn)
        {
            conn->control_stream->command("bfetch_rcs"s, std::move(payload), std::move(func));
            log::debug(logcat, "Dispatched bootstrap fetch request!");
            return;
        }

        _router.loop()->call([this, source, payload, f = std::move(func), rid = rid]() {
            connect_and_send(rid, "bfetch_rcs"s, std::move(payload), std::move(f));
        });
    }

    void LinkManager::handle_fetch_bootstrap_rcs(oxen::quic::message m)
    {
        // this handler should not be registered for clients
        assert(_router.is_service_node());
        log::critical(logcat, "Handling bootstrap fetch request...");

        std::optional<RemoteRC> remote;
        size_t quantity;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            if (btdc.skip_until("local"))
                remote.emplace(btdc.consume_dict_data());

            quantity = btdc.require<size_t>("quantity");
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "Exception handling bootstarp RC Fetch request (body:{}): {}", m.body(), e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        if (remote)
        {
            auto is_snode = _router.is_service_node();
            auto rid = remote->router_id();

            if (is_snode)
            {
                // we already insert the
                // TESTNET: REMOVE BEFORE TESTING NONLOCALLY
                // node_db->put_rc(*remote);

                auto remote_rc = *remote;

                if (node_db->registered_routers().count(remote_rc.router_id()))
                {
                    node_db->put_rc_if_newer(remote_rc);
                    log::critical(
                        logcat,
                        "Bootstrap node confirmed RID:{} is registered; approving fetch request and saving RC!",
                        remote_rc.router_id());
                    _router.loop()->call_soon([&, remote_rc]() { gossip_rc(_router.local_rid(), remote_rc); });
                }
                else
                    log::critical(
                        logcat,
                        "Bootstrap node failed to confirm RID:{} is registered; something is wrong",
                        remote_rc.router_id());
            }
        }

        auto& src = node_db->get_known_rcs();
        auto count = src.size();

        // if quantity is 0, then the service node requesting this wants all the RC's; otherwise,
        // send the amount requested in the message
        quantity = quantity == 0 ? count : quantity;

        auto now = llarp::time_now_ms();
        size_t i = 0;

        oxenc::bt_dict_producer btdp;

        {
            auto sublist = btdp.append_list("rcs");

            if (count == 0)
                log::error(logcat, "No known RCs locally to send!");
            else
            {
                for (const auto& rc : src)
                {
                    if (not rc.is_expired(now))
                        sublist.append_encoded(rc.view());

                    if (++i >= quantity)
                        break;
                }
            }
        }

        m.respond(std::move(btdp).str(), count == 0);
    }

    void LinkManager::fetch_rcs(
        const RouterID& source, std::string payload, std::function<void(oxen::quic::message m)> func)
    {
        // this handler should not be registered for service nodes
        assert(not _router.is_service_node());

        send_control_message(source, "fetch_rcs", std::move(payload), std::move(func));
    }

    void LinkManager::handle_fetch_rcs(oxen::quic::message m)
    {
        log::critical(logcat, "Handling FetchRC request...");
        // this handler should not be registered for clients
        assert(_router.is_service_node());

        std::set<RouterID> explicit_ids;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};

            {
                auto btlc = btdc.require<oxenc::bt_list_consumer>("explicit_ids");

                while (not btlc.is_finished())
                    explicit_ids.emplace(btlc.consume<ustring_view>().data());
            }
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "Exception handling RC Fetch request: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        oxenc::bt_dict_producer btdp;

        {
            auto sublist = btdp.append_list("rcs");

            int count = 0;
            for (const auto& rid : explicit_ids)
            {
                if (auto maybe_rc = node_db->get_rc_by_rid(rid))
                {
                    sublist.append_encoded(maybe_rc->view());
                    ++count;
                }
            }

            log::critical(logcat, "Returning {} RCs for FetchRC request...", count);
        }

        m.respond(std::move(btdp).str());
    }

    void LinkManager::fetch_router_ids(
        const RouterID& via, std::string payload, std::function<void(oxen::quic::message m)> func)
    {
        // this handler should not be registered for service nodes
        assert(not _router.is_service_node());

        log::critical(logcat, "payload: {}", payload);

        send_control_message(via, "fetch_rids"s, std::move(payload), std::move(func));
    }

    void LinkManager::handle_fetch_router_ids(oxen::quic::message m)
    {
        log::critical(logcat, "Handling FetchRIDs request...");
        // this handler should not be registered for clients
        assert(_router.is_service_node());

        RouterID source;
        RouterID local = router().local_rid();

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            source.from_network_address(btdc.require<std::string_view>("source"));
        }
        catch (const std::exception& e)
        {
            log::critical(logcat, "Error fulfilling FetchRIDs request: {}; body: {}", e.what(), m.body());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        if (source != local)
        {
            log::critical(
                logcat,
                "Relaying FetchRID request (body: {}) to intended target RID:{}",
                buffer_printer{m.body()},
                source);

            auto payload = FetchRIDMessage::serialize(source);
            send_control_message(
                source, "fetch_rids"s, std::move(payload), [original = std::move(m)](oxen::quic::message msg) mutable {
                    original.respond(msg.body_str(), msg.is_error());
                });
            return;
        }

        const auto& known_rids = node_db->get_known_rids();
        oxenc::bt_dict_producer btdp;

        {
            auto btlp = btdp.append_list("routers");

            for (const auto& rid : known_rids)
                btlp.append(rid.to_view());
        }

        btdp.append_signature("signature", [this](ustring_view to_sign) {
            std::array<unsigned char, 64> sig;

            if (!crypto::sign(const_cast<unsigned char*>(sig.data()), _router.identity(), to_sign))
                throw std::runtime_error{"Failed to sign fetch RouterIDs response"};

            return sig;
        });

        log::critical(logcat, "Returning ALL ({}) locally held RIDs to FetchRIDs request!", known_rids.size());
        m.respond(std::move(btdp).str());
    }

    void LinkManager::handle_resolve_ons(std::string_view body, std::function<void(std::string)> respond)
    {
        std::string name_hash;

        try
        {
            oxenc::bt_dict_consumer btdp{body};

            name_hash = btdp.require<std::string>("H");
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            respond(messages::ERROR_RESPONSE);
            return;
        }

        _router.rpc_client()->lookup_ons_hash(
            name_hash,
            [respond =
                 std::move(respond)]([[maybe_unused]] std::optional<service::EncryptedONSRecord> maybe_enc) mutable {
                if (maybe_enc)
                    respond(maybe_enc->bt_encode());
                else
                    respond(serialize_response({{messages::STATUS_KEY, FindNameMessage::NOT_FOUND}}));
            });
    }

    void LinkManager::handle_resolve_ons_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(logcat, "FindNameMessage request timed out!");
            return;
        }

        std::string payload;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            payload = btdc.require<std::string>(m ? "E" : messages::STATUS_KEY);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        if (m)
        {
            // TODO: wtf
        }
        else
        {
            if (payload == "ERROR")
            {
                log::info(logcat, "FindNameMessage failed with unkown error!");

                // resend?
            }
            else if (payload == FindNameMessage::NOT_FOUND)
            {
                log::info(logcat, "FindNameMessage failed with unkown error!");
                // what to do here?
            }
            else
                log::info(logcat, "FindNameMessage failed with unkown error!");
        }
    }

    void LinkManager::handle_publish_intro(std::string_view body, std::function<void(std::string)> respond)
    {
        service::EncryptedIntroSet enc;
        std::string introset;
        uint64_t is_relayed, relay_order;

        try
        {
            oxenc::bt_dict_consumer btdc_a{body};

            introset = btdc_a.require<std::string>("I");
            relay_order = btdc_a.require<uint64_t>("O");
            is_relayed = btdc_a.require<uint64_t>("R");

            enc = *service::EncryptedIntroSet::construct(std::move(introset));
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            respond(messages::ERROR_RESPONSE);
            return;
        }

        const auto addr = dht::Key_t{reinterpret_cast<uint8_t*>(enc.derived_signing_key.data())};
        const auto local_key = _router.rc().router_id();

        if (not enc.verify())
        {
            log::error(logcat, "Received PublishIntroMessage with invalid introset: {}", introset);
            respond(serialize_response({{messages::STATUS_KEY, PublishIntroMessage::INVALID_INTROSET}}));
            return;
        }

        auto closest_rcs = _router.node_db()->find_many_closest_to(addr, path::DEFAULT_PATHS_HELD);

        if (closest_rcs.size() != path::DEFAULT_PATHS_HELD)
        {
            log::error(logcat, "Received PublishIntroMessage but only know {} nodes", closest_rcs.size());
            respond(serialize_response({{messages::STATUS_KEY, PublishIntroMessage::INSUFFICIENT}}));
            return;
        }

        if (is_relayed)
        {
            if (relay_order >= path::DEFAULT_PATHS_HELD)
            {
                log::error(logcat, "Received PublishIntroMessage with invalide relay order: {}", relay_order);
                respond(serialize_response({{messages::STATUS_KEY, PublishIntroMessage::INVALID_ORDER}}));
                return;
            }

            log::info(logcat, "Relaying PublishIntroMessage for {}", addr);

            const auto& peer_rc = closest_rcs[relay_order];
            const auto& peer_key = peer_rc.router_id();

            if (peer_key == local_key)
            {
                log::info(
                    logcat,
                    "Received PublishIntroMessage in which we are peer index {}.. storing introset",
                    relay_order);

                _router.contacts().put_intro(std::move(enc));
                respond(messages::OK_RESPONSE);
            }
            else
            {
                log::info(logcat, "Received PublishIntroMessage; propagating to peer index {}", relay_order);

                send_control_message(
                    peer_key,
                    "publish_intro",
                    PublishIntroMessage::serialize(enc, relay_order, is_relayed),
                    [respond = std::move(respond)](oxen::quic::message m) mutable {
                        if (m.timed_out)
                            return;  // drop if timed out; requester will have timed out as well
                        respond(m.body_str());
                    });
            }

            return;
        }

        int rc_index = -1, index = 0;

        for (const auto& rc : closest_rcs)
        {
            if (rc.router_id() == local_key)
            {
                rc_index = index;
                break;
            }
            ++index;
        }

        if (rc_index >= 0)
        {
            log::info(logcat, "Received PublishIntroMessage for {}; we are candidate {}", addr, relay_order);

            _router.contacts().put_intro(std::move(enc));
            respond(messages::OK_RESPONSE);
        }
        else
            log::warning(logcat, "Received non-relayed PublishIntroMessage from {}; we are not the candidate", addr);
    }

    // DISCUSS: I feel like ::handle_publish_intro_response should be the callback that handles the
    // response to a relayed publish_intro (above line 1131-ish)

    void LinkManager::handle_publish_intro_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(logcat, "PublishIntroMessage timed out!");
            return;
        }

        std::string payload;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            payload = btdc.require<std::string>(messages::STATUS_KEY);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        if (m)
        {
            // DISCUSS: not sure what to do on success of a publish intro command?
        }
        else
        {
            if (payload == "ERROR")
            {
                log::info(logcat, "PublishIntroMessage failed with remote exception!");
                // Do something smart here probably
                return;
            }

            log::info(logcat, "PublishIntroMessage failed with error code: {}", payload);

            if (payload == PublishIntroMessage::INVALID_INTROSET)
            {
            }
            else if (payload == PublishIntroMessage::EXPIRED)
            {
            }
            else if (payload == PublishIntroMessage::INSUFFICIENT)
            {
            }
            else if (payload == PublishIntroMessage::INVALID_ORDER)
            {
            }
        }
    }

    void LinkManager::handle_find_intro(std::string_view body, std::function<void(std::string)> respond)
    {
        ustring location;
        uint64_t relay_order, is_relayed;

        try
        {
            oxenc::bt_dict_consumer btdc{body};

            relay_order = btdc.require<uint64_t>("O");
            is_relayed = btdc.require<uint64_t>("R");
            location = btdc.require<ustring>("S");
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            respond(messages::ERROR_RESPONSE);
            return;
        }

        const auto addr = dht::Key_t{location.data()};

        if (is_relayed)
        {
            if (relay_order >= path::DEFAULT_PATHS_HELD)
            {
                log::warning(logcat, "Received FindIntroMessage with invalid relay order: {}", relay_order);
                respond(serialize_response({{messages::STATUS_KEY, FindIntroMessage::INVALID_ORDER}}));
                return;
            }

            auto closest_rcs = _router.node_db()->find_many_closest_to(addr, path::DEFAULT_PATHS_HELD);

            if (closest_rcs.size() != path::DEFAULT_PATHS_HELD)
            {
                log::error(logcat, "Received FindIntroMessage but only know {} nodes", closest_rcs.size());
                respond(serialize_response({{messages::STATUS_KEY, FindIntroMessage::INSUFFICIENT_NODES}}));
                return;
            }

            log::info(logcat, "Relaying FindIntroMessage for {}", addr);

            const auto& peer_rc = closest_rcs[relay_order];
            const auto& peer_key = peer_rc.router_id();

            send_control_message(
                peer_key,
                "find_intro",
                FindIntroMessage::serialize(addr, is_relayed, relay_order),
                [respond = std::move(respond)](oxen::quic::message relay_response) mutable {
                    if (relay_response)
                        log::info(
                            logcat,
                            "Relayed FindIntroMessage returned successful response; transmitting "
                            "to initial "
                            "requester");
                    else if (relay_response.timed_out)
                        log::critical(logcat, "Relayed FindIntroMessage timed out! Notifying initial requester");
                    else
                        log::critical(logcat, "Relayed FindIntroMessage failed! Notifying initial requester");

                    respond(relay_response.body_str());
                });
        }
        else
        {
            if (auto maybe_intro = _router.contacts().get_encrypted_introset(addr))
                respond(serialize_response({{"INTROSET", maybe_intro->bt_encode()}}));
            else
            {
                log::warning(logcat, "Received FindIntroMessage with relayed == false and no local introset entry");
                respond(serialize_response({{messages::STATUS_KEY, FindIntroMessage::NOT_FOUND}}));
            }
        }
    }

    void LinkManager::handle_find_intro_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(logcat, "FindIntroMessage timed out!");
            return;
        }

        std::string payload;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            payload = btdc.require<std::string>((m) ? "INTROSET" : messages::STATUS_KEY);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        // success case, neither timed out nor errored
        if (m)
        {
            if (auto enc = service::EncryptedIntroSet::construct(payload))
            {
                _router.contacts().put_intro(std::move(*enc));
            }
        }
        else
        {
            log::info(logcat, "FindIntroMessage failed with error: {}", payload);
            // Do something smart here probably
        }
    }

    void LinkManager::handle_path_build(oxen::quic::message m, const RouterID& from)
    {
        if (!_router.path_context()->is_transit_allowed())
        {
            log::warning(logcat, "got path build request when not permitting transit");
            m.respond(PathBuildMessage::NO_TRANSIT, true);
            return;
        }

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            auto payload_list = Frames::deserialize(btlc);

            if (payload_list.size() != path::MAX_LEN)
            {
                log::info(logcat, "Path build message with wrong number of frames");
                m.respond(PathBuildMessage::BAD_FRAMES, true);
                return;
            }

            log::debug(logcat, "Deserializing frame: {}", buffer_printer{payload_list.front()});
            oxenc::bt_dict_consumer hop_dict{payload_list.front()};

            auto [nonce, other_pubkey, hop_payload] = PathBuildMessage::deserialize_hop(hop_dict, _router.local_rid());

            log::debug(logcat, "Deserializing hop payload: {}", buffer_printer{hop_payload});
            oxenc::bt_dict_consumer hop_info{hop_payload};

            auto hop = path::TransitHop::deserialize_hop(hop_info, from, _router, other_pubkey, nonce);

            hop->started = _router.now();
            set_conn_persist(hop->downstream(), hop->expiry_time() + 10s);

            // we are terminal hop and everything is okay
            if (hop->upstream() == _router.local_rid())
            {
                log::info(logcat, "We are the terminal hop; path build succeeded");
                hop->terminal_hop = true;
                _router.path_context()->put_transit_hop(std::move(hop));
                return m.respond(messages::OK_RESPONSE, false);
            }

            // pop our frame, to be randomized after onion step and appended
            auto end_frame = std::move(payload_list.front());
            payload_list.pop_front();
            auto onion_nonce = SymmNonce{nonce.data()} ^ hop->nonceXOR;

            // (de-)onion each further frame using the established shared secret and
            // onion_nonce = nonce ^ nonceXOR
            // Note: final value passed to crypto::onion is xor factor, but that's for *after* the
            // onion round to compute the return value, so we don't care about it.
            for (auto& element : payload_list)
            {
                crypto::onion(element.data(), element.size(), hop->shared, onion_nonce, onion_nonce);
            }

            // randomize final frame.  could probably paste our frame on the end and onion it with
            // the rest, but it gains nothing over random.
            randombytes(end_frame.data(), end_frame.size());
            payload_list.push_back(std::move(end_frame));

            auto upstream = hop->upstream();

            send_control_message(
                std::move(upstream),
                "path_build",
                Frames::serialize(payload_list),
                [this, transit_hop = std::move(hop), prev_message = std::move(m)](oxen::quic::message m) mutable {
                    if (m)
                    {
                        log::info(
                            logcat,
                            "Upstream returned successful path build response; locally storing Hop and relaying");
                        _router.path_context()->put_transit_hop(std::move(transit_hop));
                        return prev_message.respond(messages::OK_RESPONSE, false);
                    }
                    if (m.timed_out)
                        log::info(logcat, "Upstream timed out on path build; relaying timeout");
                    else
                        log::info(logcat, "Upstream returned path build failure; relaying response");

                    return prev_message.respond(m.body(), m.is_error());
                });
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}: input: {}", e.what(), m.body());
            // We can respond with the exception string, as all exceptions thrown in the parsing functions
            // (ex: `TransitHop::deserialize_hop(...)`) contain the correct response bodies
            m.respond(e.what(), true);
            return;
        }
    }

    void LinkManager::handle_path_latency(oxen::quic::message m)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }
    }

    void LinkManager::handle_path_latency_response(oxen::quic::message m)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            // m.respond(serialize_response({{messages::STATUS_KEY, "EXCEPTION"}}), true);
            return;
        }
    }

    void LinkManager::handle_path_transfer(oxen::quic::message m)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }
    }

    void LinkManager::handle_path_transfer_response(oxen::quic::message m)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }
    }

    void LinkManager::handle_obtain_exit(oxen::quic::message m)
    {
        [[maybe_unused]] uint64_t flag;
        ustring_view sig;
        std::string_view dict_data;

        HopID txid;
        RouterID target;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();

            {
                oxenc::bt_dict_consumer btdc{dict_data};

                flag = btdc.require<uint64_t>("E");
                target.from_string(btdc.require<std::string_view>("I"));
                txid.from_string(btdc.require<std::string_view>("T"));
            }

            sig = to_usv(btlc.consume_string_view());
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            throw;
        }

        auto transit_hop = _router.path_context()->get_transit_hop(txid);

        const auto rx_id = transit_hop->rxid();

        // TODO:
        auto success = (crypto::verify(to_usv(target.to_view()), to_usv(dict_data), sig)
                        /* and _router.exit_context()->obtain_new_exit(PubKey{pubkey.data()}, rx_id, flag != 0) */);

        m.respond(ObtainExitMessage::sign_and_serialize_response(_router.identity(), txid), not success);
    }

    void LinkManager::handle_obtain_exit_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(logcat, "ObtainExitMessage timed out!");
            return;
        }
        if (m.is_error())
        {
            // TODO: what to do here
        }

        std::string_view dict_data;
        ustring_view sig;

        HopID txid;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();

            {
                oxenc::bt_dict_consumer btdc{dict_data};
                txid.from_string(btdc.require<std::string_view>("T"));
            }

            sig = to_usv(btlc.consume_string_view());
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            throw;
        }

        if (auto path_ptr = _router.path_context()->get_path(txid))
        {
            if (crypto::verify(_router.local_rid(), to_usv(dict_data), sig))
                path_ptr->enable_exit_traffic();
        }
        else
        {
            log::critical(logcat, "Could not find path (txid:{}) for ObtainExitMessage!", txid.to_view());
        }
    }

    void LinkManager::handle_update_exit(oxen::quic::message m)
    {
        std::string_view path_id, dict_data;
        ustring_view sig;

        HopID txid;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();
            oxenc::bt_dict_consumer btdc{dict_data};

            sig = to_usv(btlc.consume_string_view());
            path_id = btdc.require<std::string_view>("P");
            txid.from_string(btdc.require<std::string_view>("T"));
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        auto transit_hop = _router.path_context()->get_transit_hop(txid);

        // TODO:
        // if (auto exit_ep =
        //         _router.exit_context().find_endpoint_for_path(PathID_t{to_usv(path_id).data()}))
        // {
        //   if (crypto::verify(exit_ep->PubKey().data(), to_usv(dict_data), sig))
        //   {
        //     (exit_ep->UpdateLocalPath(transit_hop->info.rxID))
        //         ? m.respond(UpdateExitMessage::sign_and_serialize_response(_router.identity(),
        //         tx_id)) : m.respond(
        //             serialize_response({{messages::STATUS_KEY,
        //             UpdateExitMessage::UPDATE_FAILED}}), true);
        //   }
        //   // If we fail to verify the message, no-op
        // }
    }

    void LinkManager::handle_update_exit_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(logcat, "UpdateExitMessage timed out!");
            return;
        }
        if (m.is_error())
        {
            // TODO: what to do here
        }

        std::string_view dict_data;
        ustring_view sig;

        HopID txid;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();

            {
                oxenc::bt_dict_consumer btdc{dict_data};
                txid.from_string(btdc.require<std::string_view>("T"));
            }

            sig = to_usv(btlc.consume_string_view());
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        if (auto path_ptr = _router.path_context()->get_path(txid))
        {
            if (crypto::verify(_router.local_rid(), to_usv(dict_data), sig))
            {
                // if (path_ptr->update_exit(std::stoul(tx_id)))
                // {
                //     // TODO: talk to tom and Jason about how this stupid shit was a no-op originally
                //     // see Path::HandleUpdateExitVerifyMessage
                // }
                // else
                // {
                // }
            }
        }
        else
        {
            log::critical(logcat, "Could not find path (txid:{}) for UpdateExitMessage!", txid.to_view());
        }
    }

    void LinkManager::handle_close_exit(oxen::quic::message m)
    {
        std::string_view dict_data;
        ustring_view sig;

        HopID txid;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();

            {
                oxenc::bt_dict_consumer btdc{dict_data};
                txid.from_string(btdc.require<std::string_view>("T"));
            }

            sig = to_usv(btlc.consume_string_view());
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        auto transit_hop = _router.path_context()->get_transit_hop(txid);

        const auto rx_id = transit_hop->rxid();

        // TODO:
        // if (auto exit_ep = router().exit_context().find_endpoint_for_path(rx_id))
        // {
        //   if (crypto::verify(exit_ep->PubKey().data(), to_usv(dict_data), sig))
        //   {
        //     exit_ep->Close();
        //     m.respond(CloseExitMessage::sign_and_serialize_response(_router.identity(), tx_id));
        //   }
        // }

        m.respond(serialize_response({{messages::STATUS_KEY, CloseExitMessage::UPDATE_FAILED}}), true);
    }

    void LinkManager::handle_close_exit_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(logcat, "CloseExitMessage timed out!");
            return;
        }
        if (m.is_error())
        {
            // TODO: what to do here
        }

        std::string_view nonce, dict_data;
        ustring_view sig;

        HopID txid;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();

            {
                oxenc::bt_dict_consumer btdc{dict_data};
                txid.from_string(btdc.require<std::string_view>("T"));
                nonce = btdc.require<std::string_view>("Y");
            }

            sig = to_usv(btlc.consume_string_view());
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        if (auto path_ptr = _router.path_context()->get_path(txid))
        {
            //
        }
        else
        {
            log::critical(logcat, "Could not find path (txid:{}) for CloseExitMessage!", txid.to_view());
        }
        // TODO:
        // if (path_ptr->SupportsAnyRoles(path::ePathRoleExit | path::ePathRoleSVC)
        //     and crypto::verify(_router.pubkey(), to_usv(dict_data), sig))
        //   path_ptr->mark_exit_closed();
    }

    void LinkManager::handle_path_control(oxen::quic::message m, const RouterID& /* from */)
    {
        ustring nonce, hop_id_str, payload;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            std::tie(hop_id_str, nonce, payload) = Onion::deserialize(btdc);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        auto symmnonce = SymmNonce{nonce.data()};
        HopID hopid{hop_id_str.data()};
        auto hop = _router.path_context()->get_transit_hop(hopid);

        // TODO: use "path_control" for both directions?  If not, drop message on
        // floor if we don't have the path_id in question; if we decide to make this
        // bidirectional, will need to check if we have a Path with path_id.
        if (not hop)
            return;

        symmnonce = crypto::onion(payload.data(), payload.size(), hop->shared, symmnonce, hop->nonceXOR);

        // if terminal hop, payload should contain a request (e.g. "ons_resolve"); handle and respond.
        if (hop->terminal_hop)
        {
            handle_inner_request(
                std::move(m),
                std::string{reinterpret_cast<const char*>(payload.data()), payload.size()},
                std::move(hop));
            return;
        }

        auto hop_is_rx = hop->rxid() == hopid;

        const auto& next_id = hop_is_rx ? hop->txid() : hop->rxid();
        const auto& next_router = hop_is_rx ? hop->upstream() : hop->downstream();

        std::string new_payload = Onion::serialize(symmnonce, next_id, payload);

        send_control_message(
            next_router,
            "path_control"s,
            std::move(new_payload),
            [hop_weak = hop->weak_from_this(), hopid, prev_message = std::move(m)](
                oxen::quic::message response) mutable {
                auto hop = hop_weak.lock();

                if (not hop)
                    return;

                ustring hop_id, nonce, payload;

                try
                {
                    oxenc::bt_dict_consumer btdc{response.body()};
                    std::tie(hop_id, nonce, payload) = Onion::deserialize(btdc);
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Exception: {}", e.what());
                    return;
                }

                auto symmnonce = SymmNonce{nonce.data()};
                auto resp_payload = Onion::serialize(symmnonce, HopID{hop_id.data()}, payload);
                prev_message.respond(std::move(resp_payload), false);
            });
    }

    void LinkManager::handle_inner_request(
        oxen::quic::message m, std::string payload, std::shared_ptr<path::TransitHop> hop)
    {
        std::string endpoint, body;

        try
        {
            oxenc::bt_dict_consumer btdc{payload};
            std::tie(endpoint, body) = PathControl::deserialize(btdc);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        // If a handler exists for "method", call it; else drop request on the floor.
        auto itr = path_requests.find(endpoint);

        if (itr == path_requests.end())
        {
            log::info(logcat, "Received path control request \"{}\", which has no handler.", endpoint);
            return;
        }

        auto respond = [m = std::move(m), hop_weak = hop->weak_from_this()](std::string response) mutable {
            auto hop = hop_weak.lock();
            if (not hop)
                return;  // transit hop gone, drop response

            auto n = SymmNonce::make_random();
            m.respond(Onion::serialize(n, hop->rxid(), response), false);
        };

        std::invoke(itr->second, this, std::move(body), std::move(respond));
    }

    void LinkManager::handle_initiate_session(oxen::quic::message m)
    {
        if (not m)
        {
            log::info(logcat, "Initiate session message timed out!");
            return;
        }

        NetworkAddress initiator;
        service::SessionTag tag;
        HopID pivot_txid;
        bool use_tun;
        std::optional<std::string> maybe_auth = std::nullopt;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};

            std::tie(initiator, pivot_txid, tag, use_tun, maybe_auth) =
                InitiateSession::decrypt_deserialize(btdc, _router.local_rid());

            if (not _router.session_endpoint()->validate(initiator, maybe_auth))
            {
                log::warning(logcat, "Failed to authenticate session initiation request from remote:{}", initiator);
                return m.respond(InitiateSession::AUTH_DENIED, true);
            }

            auto path_ptr = _router.path_context()->get_path(pivot_txid);

            if (not path_ptr)
            {
                log::warning(logcat, "Failed to find local path corresponding to session over pivot: {}", pivot_txid);
                return m.respond(messages::ERROR_RESPONSE, true);
            }

            if (_router.session_endpoint()->prefigure_session(
                    std::move(initiator), std::move(tag), std::move(path_ptr), use_tun))
            {
                return m.respond(messages::OK_RESPONSE);
            }

            log::warning(logcat, "Failed to configure InboundSession!");
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
        }

        m.respond(messages::ERROR_RESPONSE, true);
    }

    void LinkManager::handle_convo_intro(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(logcat, "Convo intro message timed out!");
            return;
        }

        try
        {
            //
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }
    }

}  // namespace llarp
