#include "link_manager.hpp"

#include "connection.hpp"

#include <llarp/contact/contactdb.hpp>
#include <llarp/contact/router_id.hpp>
#include <llarp/messages/dht.hpp>
#include <llarp/messages/exit.hpp>
#include <llarp/messages/fetch.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/messages/session.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path.hpp>
#include <llarp/router/router.hpp>

#include <oxenc/bt_producer.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <algorithm>
#include <exception>
#include <set>

namespace llarp
{
    static auto logcat = llarp::log::Cat("lquic");

    static constexpr auto static_shared_key = "Lokinet static shared secret key"_usv;

    static static_secret make_static_secret(const Ed25519SecretKey& sk)
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

        void Endpoint::for_each_connection(std::function<void(const RouterID&, link::Connection&)> func)
        {
            link_manager.router().loop()->call([this, func = std::move(func)]() mutable {
                for (auto& [rid, conn] : service_conns)
                    if (conn)
                        func(rid, *conn);

                if (_is_service_node)
                {
                    for (auto& [rid, conn] : client_conns)
                        if (conn)
                            func(rid, *conn);
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

                for (const auto& [_, c] : service_conns)
                {
                    if (not c)
                        continue;

                    if (c->is_inbound())
                        ++in;
                    else
                        ++out;
                }

                for (const auto& [_, c] : client_conns)
                {
                    if (not c)
                        continue;

                    if (c->is_inbound())
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
            return link_manager.router().loop()->call_get([this]() {
                size_t n{};

                for (const auto& [_, c] : service_conns)
                    n += (c != nullptr);

                return n;
            });
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

    std::set<RouterID> LinkManager::get_current_remotes() const
    {
        // invoke using Router method to wrap in call_get
        std::set<RouterID> ret{};

        for (auto& [rid, conn] : ep->service_conns)
            if (conn)
                ret.insert(rid);

        return ret;
    }

    void LinkManager::for_each_connection(std::function<void(const RouterID&, link::Connection&)> func)
    {
        if (is_stopping)
            return;

        return ep->for_each_connection(std::move(func));
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
            s->register_handler("session_init"s, [this](oxen::quic::message m) mutable {
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

        s->register_handler("publish_cc"s, [this](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_publish_cc(std::move(msg)); });
        });

        s->register_handler("find_cc"s, [this](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_find_cc(std::move(msg)); });
        });

        s->register_handler("resolve_sns"s, [this](oxen::quic::message m) mutable {
            _router.loop()->call([&, msg = std::move(m)]() mutable { handle_resolve_sns(std::move(msg)); });
        });

        log::debug(logcat, "Registered all commands for connection to remote RID:{}", remote_rid);
    }

    void LinkManager::start_tickers()
    {
        log::debug(logcat, "Starting gossip ticker...");
        _gossip_ticker = _router.loop()->call_every(
            _router._gossip_interval,
            [this]() {
                log::critical(logcat, "Regenerating and gossiping RC...");
                _router.relay_contact.resign();
                _router.save_rc();
                gossip_rc(_router.local_rid(), _router.relay_contact.to_remote());
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
              {reinterpret_cast<const char*>(_router.local_rid().data()), 32})},
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
            is_service_node() ? alpns::SERVICE_OUTBOUND : alpns::CLIENT_OUTBOUND);

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
                        log::critical(logcat, "{} accepting client connection (remote ID:{})!", us, other);
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
                                    "{} received inbound with ongoing outbound to remote "
                                    "(RID:{}); {}!",
                                    us,
                                    other,
                                    defer_to_incoming ? "deferring to inbound" : "rejecting in favor of outbound");

                                return defer_to_incoming;
                            }

                            log::critical(logcat, "{} accepting inbound from registered remote (RID:{})", us, other);
                        }
                        else
                            log::critical(
                                logcat,
                                "{} was unable to confirm remote (RID:{}) is registered; "
                                "rejecting "
                                "connection!",
                                us,
                                other);

                        return result;
                    }

                    log::critical(logcat, "{} received unknown ALPN; rejecting connection!", us);
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
            log::warning(logcat, "Could not find RelayContact for connection to rid:{}", rid);
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
                    router,
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
                KeyedAddress{rid.to_view(), remote_addr}, rid, std::move(on_open), std::move(on_close));
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

    void LinkManager::connect_to_keep_alive(size_t num_conns)
    {
        auto filter = [this](const RemoteRC& rc) -> bool {
            const auto& rid = rc.router_id();
            auto res = not ep->have_service_conn(rid);

            log::trace(logcat, "RID:{} {}", rid, res ? "ACCEPTED" : "REJECTED");

            return res;
        };

        std::optional<std::vector<RemoteRC>> rcs = std::nullopt;

        if (node_db->strict_connect_enabled())
        {
            assert(not _is_service_node);

            // TESTNET: TODO: if given strict-connects, fetch their RCs SPECIFICALLY in bootstrapping
            log::warning(logcat, "FINISH STRICT CONNECT (SEE COMMENT)");
        }

        if (auto maybe = node_db->get_n_random_rcs_conditional(num_conns, filter))
        {
            std::vector<RemoteRC>& rcs = *maybe;

            for (const auto& rc : rcs)
                connect_to(rc);
        }
        else
            log::warning(logcat, "NodeDB query for {} random RCs for connection returned none", num_conns);
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
            log::critical(logcat, "Exception handling bootstrap RC Fetch request (body:{}): {}", m.body(), e.what());
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
            log::critical(logcat, "Relaying FetchRID request (body: {}) to intended target RID:{}", m.body(), source);

            auto payload = FetchRIDMessage::serialize(source);
            send_control_message(
                source, "fetch_rids"s, std::move(payload), [original = std::move(m)](oxen::quic::message msg) mutable {
                    original.respond(msg.body(), msg.is_error());
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

    void LinkManager::_handle_resolve_sns(oxen::quic::message m, std::optional<std::string> inner_body)
    {
        log::critical(logcat, "Received request to publish client contact!");

        std::string name_hash;

        try
        {
            if (inner_body)
                name_hash = ResolveSNS::deserialize(oxenc::bt_dict_consumer{*inner_body});
            else
                name_hash = ResolveSNS::deserialize(oxenc::bt_dict_consumer{m.body()});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return m.respond(messages::ERROR_RESPONSE, true);
        }

        _router.rpc_client()->lookup_ons_hash(
            name_hash, [prev_msg = std::move(m)](std::optional<EncryptedSNSRecord> maybe_enc) mutable {
                if (maybe_enc)
                {
                    log::info(logcat, "RPC lookup successfully returned encrypted SNS record!");
                    prev_msg.respond(ResolveSNS::serialize_response(*maybe_enc));
                }
                else
                {
                    log::warning(logcat, "RPC lookup could not find SNS registry!");
                    prev_msg.respond(ResolveSNS::NOT_FOUND, true);
                }
            });
    }

    void LinkManager::handle_resolve_sns(oxen::quic::message m)
    {
        std::string name_hash;

        try
        {
            name_hash = ResolveSNS::deserialize(oxenc::bt_dict_consumer{m.body()});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return m.respond(messages::ERROR_RESPONSE, true);
        }

        _router.rpc_client()->lookup_ons_hash(
            name_hash, [prev_msg = std::move(m)](std::optional<EncryptedSNSRecord> maybe_enc) mutable {
                if (maybe_enc)
                {
                    log::info(logcat, "RPC lookup successfully returned encrypted SNS record!");
                    prev_msg.respond(ResolveSNS::serialize_response(*maybe_enc));
                }
                else
                {
                    log::warning(logcat, "RPC lookup could not find SNS registry!");
                    prev_msg.respond(ResolveSNS::NOT_FOUND, true);
                }
            });
    }

    void LinkManager::_handle_publish_cc(oxen::quic::message m, std::optional<std::string> inner_body)
    {
        log::critical(logcat, "Received request to publish client contact!");

        EncryptedClientContact enc;

        try
        {
            if (inner_body)
                enc = PublishClientContact::deserialize(oxenc::bt_dict_consumer{*inner_body});
            else
                enc = PublishClientContact::deserialize(oxenc::bt_dict_consumer{m.body()});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}: payload: {}", e.what(), buffer_printer{m.body()});
            return m.respond(messages::ERROR_RESPONSE, true);
        }

        if (enc.is_expired())
        {
            log::warning(logcat, "Received expired EncryptedClientContact!");
            return m.respond(PublishClientContact::EXPIRED, true);
        }

        if (not enc.verify())
        {
            log::warning(logcat, "Received invalid EncryptedClientContact!");
            return m.respond(PublishClientContact::INVALID, true);
        }

        auto dht_key = enc.key();
        auto local_rid = _router.local_rid();

        auto closest_rcs = _router.node_db()->find_many_closest_to(dht_key, path::DEFAULT_PATHS_HELD);

        for (const auto& rc : closest_rcs)
        {
            if (rc.router_id() == local_rid)
            {
                log::info(
                    logcat,
                    "Received PublishClientContact (key: {}) for which we are a candidate; accepting...",
                    dht_key);
                _router.contact_db().put_cc(std::move(enc));
                return m.respond(messages::OK_RESPONSE);
            }
        }

        const auto& peer_key = closest_rcs.begin()->router_id();

        log::info(logcat, "Received PublishClientContact; propagating to peer (key: {})...", peer_key);

        send_control_message(
            peer_key,
            "publish_cc",
            PublishClientContact::serialize(std::move(enc)),
            [prev_msg = std::move(m)](oxen::quic::message msg) mutable {
                log::info(
                    logcat,
                    "Relayed PublishClientContact {}! Relaying response...",
                    msg                 ? "succeeded"
                        : msg.timed_out ? "timed out"
                                        : "failed");
                prev_msg.respond(msg.body_str(), msg.is_error());
            });
    }

    void LinkManager::handle_publish_cc(oxen::quic::message m)
    {
        return _handle_publish_cc(std::move(m));
    }

    void LinkManager::_handle_find_cc(oxen::quic::message m, std::optional<std::string> inner_body)
    {
        log::critical(logcat, "Received request to find client contact!");

        dht::Key_t dht_key;

        try
        {
            if (inner_body)
                dht_key = FindClientContact::deserialize(oxenc::bt_dict_consumer{*inner_body});
            else
                dht_key = FindClientContact::deserialize(oxenc::bt_dict_consumer{m.body()});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return m.respond(messages::ERROR_RESPONSE, true);
        }

        if (auto maybe_cc = _router.contact_db().get_encrypted_cc(dht_key))
        {
            log::info(logcat, "Received FindClientContact request; returning local EncryptedClientContact...");
            return m.respond(FindClientContact::serialize_response(*maybe_cc));
        }

        auto closest_peer = _router.node_db()->find_closest_to(dht_key).router_id();

        if (closest_peer == _router.local_rid())
        {
            log::warning(
                logcat,
                "We are closest peer for FindClientContact request (key: {}); no EncryptedClientContact found locally!",
                dht_key);
            return m.respond(FindClientContact::NOT_FOUND, true);
        }

        log::debug(logcat, "Relaying FindClientContactMessage for {}", dht_key);

        send_control_message(
            closest_peer,
            "find_cc"s,
            FindClientContact::serialize(dht_key),
            [prev_msg = std::move(m)](oxen::quic::message msg) mutable {
                log::info(
                    logcat,
                    "Relayed FindClientContactMessage {}! Relaying response...",
                    msg                 ? "succeeded"
                        : msg.timed_out ? "timed out"
                                        : "failed");
                prev_msg.respond(msg.body_str(), msg.is_error());
            });
    }

    void LinkManager::handle_find_cc(oxen::quic::message m)
    {
        return _handle_find_cc(std::move(m));
    }

    void LinkManager::handle_path_build(oxen::quic::message m, const RouterID& from)
    {
        if (!_router.path_context()->is_transit_allowed())
        {
            log::warning(logcat, "got path build request when not permitting transit");
            return m.respond(PATH::BUILD::NO_TRANSIT, true);
        }

        try
        {
            auto frames = ONION::deserialize_frames(m.body());
            auto n_frames = frames.size();

            if (n_frames != path::MAX_LEN)
            {
                log::info(logcat, "Path build message with wrong number of frames: {}", frames.size());
                return m.respond(PATH::BUILD::BAD_FRAMES, true);
            }

            log::trace(logcat, "Deserializing frame: {}", buffer_printer{frames.front()});

            SymmNonce nonce;
            ustring hop_payload;
            SharedSecret shared;

            std::tie(nonce, shared, hop_payload) =
                PATH::BUILD::deserialize_hop(oxenc::bt_dict_consumer{frames.front()}, _router.identity());

            log::trace(logcat, "Deserializing hop payload: {}", buffer_printer{hop_payload});

            auto hop = path::TransitHop::deserialize_hop(
                oxenc::bt_dict_consumer{hop_payload}, from, _router, std::move(shared));

            // we are terminal hop and everything is okay
            if (hop->upstream() == _router.local_rid())
            {
                log::info(logcat, "We are the terminal hop; path build succeeded");
                if (not hop->terminal_hop)
                {
                    // TESTNET: remove this eventually
                    log::critical(
                        logcat, "DANIEL FIX THIS: Hop is terminal hop; constructor should have flipped this boolean");
                    hop->terminal_hop = true;
                }
                _router.path_context()->put_transit_hop(std::move(hop));
                return m.respond(messages::OK_RESPONSE, false);
            }

            // rotate our frame to the back
            std::ranges::rotate(frames, frames.begin() + 1);

            // clear our frame, to be randomized after onion step and appended
            frames.back().clear();

            auto onion_nonce = nonce ^ hop->nonceXOR;

            // (de-)onion each further frame using the established shared secret and
            // onion_nonce = nonce ^ nonceXOR
            // Note: final value passed to crypto::onion is xor factor, but that's for *after* the
            // onion round to compute the return value, so we don't care about it.
            // for (auto& element : frames)
            for (size_t i = 0; i < n_frames - 1; ++i)
            {
                crypto::onion(
                    reinterpret_cast<unsigned char*>(frames[i].data()),
                    frames[i].size(),
                    hop->shared,
                    onion_nonce,
                    onion_nonce);
            }

            // randomize final frame
            randombytes(reinterpret_cast<unsigned char*>(frames.back().data()), frames.back().size());

            auto upstream = hop->upstream();

            send_control_message(
                std::move(upstream),
                "path_build",
                ONION::serialize_frames(std::move(frames)),
                [this, transit_hop = std::move(hop), prev_message = std::move(m)](oxen::quic::message m) mutable {
                    if (m)
                    {
                        log::info(
                            logcat,
                            "Upstream returned successful path build response; locally storing Hop ({}) and relaying",
                            transit_hop->to_string());
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
            return m.respond(e.what(), true);
        }
    }

    void LinkManager::handle_path_control(oxen::quic::message m, const RouterID& /* from */)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        HopID hop_id;
        std::string payload;
        SymmNonce nonce;

        try
        {
            std::tie(hop_id, nonce, payload) = ONION::deserialize_hop(oxenc::bt_dict_consumer{m.body()});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return m.respond(messages::ERROR_RESPONSE, true);
        }

        auto hop = _router.path_context()->get_transit_hop(hop_id);

        // TODO: when using path control messages for responses, check for the Path
        // with the corresponding ID, de-onion, etc
        if (not hop)
        {
            log::warning(logcat, "Received path control with unknown next hop (ID: {})", hop_id);
            return m.respond(messages::ERROR_RESPONSE, true);
        }

        auto onion_nonce = nonce ^ hop->nonceXOR;

        crypto::onion(
            reinterpret_cast<unsigned char*>(payload.data()), payload.size(), hop->shared, onion_nonce, hop->nonceXOR);

        // if terminal hop, payload should contain a request (e.g. "ons_resolve"); handle and respond.
        if (hop->terminal_hop)
        {
            log::debug(logcat, "We are terminal hop for path request: {}", hop->to_string());
            return handle_path_request(std::move(m), std::move(payload));
        }

        log::debug(logcat, "We are intermediate hop for path request: {}", hop->to_string());

        auto hop_is_rx = hop->rxid() == hop_id;

        const auto& next_id = hop_is_rx ? hop->txid() : hop->rxid();
        const auto& next_router = hop_is_rx ? hop->upstream() : hop->downstream();

        std::string new_payload = ONION::serialize_hop(next_id.to_view(), onion_nonce, std::move(payload));

        send_control_message(
            next_router,
            "path_control",
            std::move(new_payload),
            [hop_weak = hop->weak_from_this(), hop_id, prev_message = std::move(m)](
                oxen::quic::message response) mutable {
                auto hop = hop_weak.lock();

                if (not hop)
                {
                    log::warning(logcat, "Received response to path control message with non-existent TransitHop!");
                    return prev_message.respond(messages::ERROR_RESPONSE, true);
                }

                if (response)
                    log::info(logcat, "Path control message returned successfully!");
                else if (response.timed_out)
                    log::warning(logcat, "Path control message returned as time out!");
                else
                    log::warning(logcat, "Path control message returned as error!");

                prev_message.respond(response.body_str(), response.is_error());

                // TODO: onion encrypt path message responses
                // HopID hop_id;
                // SymmNonce nonce;
                // std::string payload;

                // try
                // {
                //     std::tie(hop_id, nonce, payload) =
                //     ONION::deserialize_hop(oxenc::bt_dict_consumer{response.body()});
                // }
                // catch (const std::exception& e)
                // {
                //     log::warning(logcat, "Exception: {}; payload: {}", e.what(), buffer_printer{response.body()});
                //     return prev_message.respond(messages::ERROR_RESPONSE, true);
                // }

                // auto resp_payload = ONION::serialize_hop(hop_id.to_view(), nonce, std::move(payload));
                // prev_message.respond(std::move(resp_payload), false);
            });
    }

    void LinkManager::handle_path_data_message(bstring message)
    {
        HopID hop_id;
        std::string payload;
        SymmNonce nonce;

        try
        {
            std::tie(hop_id, nonce, payload) = ONION::deserialize_hop(oxenc::bt_dict_consumer{message});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}", e.what());
            return;
        }

        auto hop = _router.path_context()->get_transit_hop(hop_id);

        if (not hop)
        {
            log::warning(logcat, "Received path data with unknown next hop (ID: {})", hop_id);
            return;
        }

        nonce = crypto::onion(
            reinterpret_cast<unsigned char*>(payload.data()), payload.size(), hop->shared, nonce, hop->nonceXOR);

        // if terminal hop, pass to the correct path expecting to receive this message
        if (hop->terminal_hop)
        {
            NetworkAddress sender;
            bstring data;

            try
            {
                oxenc::bt_dict_consumer btdc{payload};
                std::tie(sender, data) = PATH::DATA::deserialize(btdc);

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
            auto hop_is_rx = hop->rxid() == hop_id;

            const auto& next_id = hop_is_rx ? hop->txid() : hop->rxid();
            const auto& next_router = hop_is_rx ? hop->upstream() : hop->downstream();

            std::string new_payload = ONION::serialize_hop(next_id.to_view(), nonce, std::move(payload));

            send_data_message(next_router, std::move(new_payload));
        }
    }

    void LinkManager::handle_path_request(oxen::quic::message m, std::string payload)
    {
        std::string endpoint, body;

        try
        {
            std::tie(endpoint, body) = PATH::CONTROL::deserialize(oxenc::bt_dict_consumer{payload});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Exception: {}; Payload: {}", e.what(), buffer_printer{payload});
            return m.respond(messages::serialize_response({{messages::STATUS_KEY, e.what()}}), true);
        }

        if (auto it = path_requests.find(endpoint); it != path_requests.end())
        {
            log::debug(logcat, "Received path control request (`{}`); invoking endpoint...", endpoint);
            std::invoke(it->second, this, std::move(m), std::move(body));
        }
        else
            log::warning(logcat, "Received path control request (`{}`), which has no local handler!", endpoint);
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
        std::shared_ptr<path::Path> path_ptr;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};

            std::tie(initiator, pivot_txid, tag, use_tun, maybe_auth) =
                InitiateSession::decrypt_deserialize(btdc, _router.identity());

            if (not _router.session_endpoint()->validate(initiator, maybe_auth))
            {
                log::warning(logcat, "Failed to authenticate session initiation request from remote:{}", initiator);
                return m.respond(InitiateSession::AUTH_DENIED, true);
            }

            path_ptr = _router.path_context()->get_path(pivot_txid);

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

        _router.path_context()->drop_path(path_ptr);
        m.respond(messages::ERROR_RESPONSE, true);
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
            return m.respond(messages::ERROR_RESPONSE, true);
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
