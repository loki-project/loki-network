#include "link_manager.hpp"

#include "connection.hpp"
#include "contacts.hpp"

#include <llarp/messages/dht.hpp>
#include <llarp/messages/exit.hpp>
#include <llarp/messages/fetch.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path.hpp>
#include <llarp/router/router.hpp>

#include <oxenc/bt_producer.h>

#include <algorithm>
#include <exception>
#include <set>

namespace llarp
{
    namespace link
    {
        Endpoint::Endpoint(std::shared_ptr<oxen::quic::Endpoint> ep, LinkManager& lm)
            : endpoint{std::move(ep)}, link_manager{lm}, _is_service_node{link_manager.is_service_node()}
        {}

        std::shared_ptr<link::Connection> Endpoint::get_service_conn(const RouterID& rid) const
        {
            if (auto itr = service_conns.find(rid); itr != service_conns.end())
                return itr->second;

            return nullptr;
        }

        std::shared_ptr<link::Connection> Endpoint::get_conn(const RouterID& rid) const
        {
            if (auto itr = service_conns.find(rid); itr != service_conns.end())
                return itr->second;

            if (_is_service_node)
            {
                if (auto itr = client_conns.find(rid); itr != client_conns.end())
                    return itr->second;
            }

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

        void Endpoint::for_each_connection(std::function<void(link::Connection&)> func)
        {
            for (const auto& [rid, conn] : service_conns)
                func(*conn);

            if (_is_service_node)
            {
                for (const auto& [rid, conn] : client_conns)
                    func(*conn);
            }
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

        std::tuple<size_t, size_t, size_t, size_t> Endpoint::connection_stats() const
        {
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
        }

        size_t Endpoint::num_client_conns() const
        {
            return client_conns.size();
        }

        size_t Endpoint::num_router_conns() const
        {
            return service_conns.size();
        }
    }  // namespace link

    std::tuple<size_t, size_t, size_t, size_t> LinkManager::connection_stats() const
    {
        return ep.connection_stats();
    }

    size_t LinkManager::get_num_connected_routers() const
    {
        return ep.num_router_conns();
    }

    size_t LinkManager::get_num_connected_clients() const
    {
        return ep.num_client_conns();
    }

    using messages::serialize_response;

    void LinkManager::for_each_connection(std::function<void(link::Connection&)> func)
    {
        if (is_stopping)
            return;

        return ep.for_each_connection(func);
    }

    void LinkManager::register_commands(
        const std::shared_ptr<oxen::quic::BTRequestStream>& s, const RouterID& router_id, bool)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        s->register_handler("bfetch_rcs"s, [this](oxen::quic::message m) {
            _router.loop()->call([this, msg = std::move(m)]() mutable { handle_fetch_bootstrap_rcs(std::move(msg)); });
        });

        s->register_handler("fetch_rcs"s, [this](oxen::quic::message m) {
            _router.loop()->call([this, msg = std::move(m)]() mutable { handle_fetch_rcs(std::move(msg)); });
        });

        s->register_handler("fetch_rids"s, [this](oxen::quic::message m) {
            _router.loop()->call([this, msg = std::move(m)]() mutable { handle_fetch_router_ids(std::move(msg)); });
        });

        s->register_handler("path_build"s, [this, rid = router_id](oxen::quic::message m) {
            _router.loop()->call(
                [this, &rid, msg = std::move(m)]() mutable { handle_path_build(std::move(msg), rid); });
        });

        s->register_handler("path_control"s, [this, rid = router_id](oxen::quic::message m) {
            _router.loop()->call(
                [this, &rid, msg = std::move(m)]() mutable { handle_path_control(std::move(msg), rid); });
        });

        s->register_handler("gossip_rc"s, [this](oxen::quic::message m) {
            _router.loop()->call([this, msg = std::move(m)]() mutable { handle_gossip_rc(std::move(msg)); });
        });

        for (auto& method : direct_requests)
        {
            s->register_handler(
                std::string{method.first}, [this, func = std::move(method.second)](oxen::quic::message m) {
                    _router.loop()->call([this, msg = std::move(m), func = std::move(func)]() mutable {
                        auto body = msg.body_str();
                        auto respond = [m = std::move(msg)](std::string response) mutable {
                            m.respond(std::move(response), m.is_error());
                        };
                        std::invoke(func, this, body, std::move(respond));
                    });
                });
        }

        log::critical(logcat, "Registered all commands! (RID:{})", router_id);
    }

    LinkManager::LinkManager(Router& r)
        : _router{r},
          _is_service_node{_router.is_service_node()},
          quic{std::make_unique<oxen::quic::Network>()},
          tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_keys(
              {reinterpret_cast<const char*>(_router.identity().data()), size_t{32}},
              {reinterpret_cast<const char*>(_router.identity().toPublic().data()), size_t{32}})},
          ep{startup_endpoint(), *this}
    {}

    std::unique_ptr<LinkManager> LinkManager::make(Router& r)
    {
        std::unique_ptr<LinkManager> p{new LinkManager(r)};
        return p;
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
            [this](oxen::quic::connection_interface& ci) { return on_conn_open(ci); },
            [this](oxen::quic::connection_interface& ci, uint64_t ec) { return on_conn_closed(ci, ec); },
            [this](oxen::quic::dgram_interface& di, bstring dgram) { recv_data_message(di, dgram); },
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
                        log::critical(logcat, "{} node accepting client connection (remote ID:{})!", us, other);
                        ep.client_conns.emplace(other, nullptr);
                        return true;
                    }

                    if (alpn == alpns::SN_ALPNS)
                    {
                        // verify as service node!
                        bool result = node_db->registered_routers().count(other);

                        if (result)
                        {
                            auto [itr, b] = ep.service_conns.try_emplace(other, nullptr);

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
        {
            e->listen(tls_creds);
        }
        return e;
    }

    std::shared_ptr<oxen::quic::BTRequestStream> LinkManager::make_control(
        oxen::quic::connection_interface& ci, const RouterID& rid)
    {
        auto control_stream = ci.queue_incoming_stream<oxen::quic::BTRequestStream>(
            [rid = rid](oxen::quic::Stream&, uint64_t error_code) {
                log::warning(logcat, "BTRequestStream closed unexpectedly (ec:{})", error_code);
            });

        log::critical(logcat, "Queued BTStream to be opened (ID:{})", control_stream->stream_id());
        assert(control_stream->stream_id() == 0);
        register_commands(control_stream, rid);

        return control_stream;
    }

    void LinkManager::on_inbound_conn(oxen::quic::connection_interface& ci)
    {
        assert(_is_service_node);
        RouterID rid{ci.remote_key()};

        auto control = make_control(ci, rid);

        _router.loop()->call([this, ci_ptr = ci.shared_from_this(), bstream = std::move(control), rid]() {
            if (auto it = ep.service_conns.find(rid); it != ep.service_conns.end())
            {
                log::critical(logcat, "Configuring inbound connection from relay RID:{}", rid);

                it->second = std::make_shared<link::Connection>(ci_ptr, std::move(bstream));
            }
            else if (auto it = ep.client_conns.find(rid); it != ep.client_conns.end())
            {
                log::critical(logcat, "Configuring inbound connection from client RID:{}", rid);
                it->second = std::make_shared<link::Connection>(ci_ptr, std::move(bstream), false);
            }
            else
            {
                log::critical(
                    logcat,
                    "ERROR: connection accepted from RID:{} that was not logged in key "
                    "verification!",
                    rid);
            }

            log::critical(logcat, "Successfully configured inbound connection fom {}...", rid);
        });
    }

    void LinkManager::on_outbound_conn(oxen::quic::connection_interface& ci)
    {
        RouterID rid{ci.remote_key()};

        if (auto it = ep.service_conns.find(rid); it != ep.service_conns.end())
        {
            log::critical(logcat, "Fetched configured outbound connection to relay RID:{}", rid);
        }
        else
        {
            log::critical(
                logcat,
                "ERROR: connection established to RID:{} that was not logged in connection "
                "establishment!",
                rid);
        }
    }

    // TODO: should we add routes here now that Router::SessionOpen is gone?
    void LinkManager::on_conn_open(oxen::quic::connection_interface& ci)
    {
        const auto rid = RouterID{ci.remote_key()};

        log::critical(
            logcat,
            "{} (RID:{}) ESTABLISHED CONNECTION TO RID:{}",
            _is_service_node ? "SERVICE NODE" : "CLIENT",
            _router.local_rid(),
            rid);

        if (ci.is_inbound())
        {
            log::critical(logcat, "Inbound connection from {}", rid);
            on_inbound_conn(ci);
        }
        else
        {
            log::critical(logcat, "Outbound connection to {}", rid);
            on_outbound_conn(ci);
        }
        // _router.loop()->call([this, &conn_interface = ci, is_snode = _is_service_node]() {
        // });
    };

    void LinkManager::on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec)
    {
        _router.loop()->call([this, ref_id = ci.reference_id(), rid = RouterID{ci.remote_key()}, error_code = ec]() {
            log::critical(quic_cat, "Purging quic connection {} (ec:{})", ref_id, error_code);

            if (auto s_itr = ep.service_conns.find(rid); s_itr != ep.service_conns.end())
            {
                log::critical(quic_cat, "Quic connection to relay RID:{} purged successfully", rid);
                ep.service_conns.erase(s_itr);
            }
            else if (auto c_itr = ep.client_conns.find(rid); c_itr != ep.client_conns.end())
            {
                log::critical(quic_cat, "Quic connection to client RID:{} purged successfully", rid);
                ep.client_conns.erase(c_itr);
            }
            else
                log::critical(quic_cat, "Nothing to purge for quic connection {}", ref_id);
        });
    }

    bool LinkManager::send_control_message(
        const RouterID& remote, std::string endpoint, std::string body, std::function<void(oxen::quic::message m)> func)
    {
        // DISCUSS: revisit if this assert makes sense. If so, there's no need to if (func) the
        // next logic block
        // assert(func);  // makes no sense to send control message and ignore response (maybe gossip?)

        if (is_stopping)
            return false;

        if (func)
        {
            func = [this, f = std::move(func)](oxen::quic::message m) mutable {
                _router.loop()->call([func = std::move(f), msg = std::move(m)]() mutable { func(std::move(msg)); });
            };
        }

        if (auto conn = ep.get_conn(remote); conn)
        {
            log::critical(logcat, "Dispatching {} request to remote:{}", endpoint, remote);
            conn->control_stream->command(std::move(endpoint), std::move(body), std::move(func));
            return true;
        }

        log::critical(logcat, "Queueing message to ");

        _router.loop()->call(
            [this, remote, endpoint = std::move(endpoint), body = std::move(body), f = std::move(func)]() {
                connect_and_send(remote, std::move(endpoint), std::move(body), std::move(f));
            });

        return false;
    }

    bool LinkManager::send_data_message(const RouterID& remote, std::string body)
    {
        if (is_stopping)
            return false;

        if (auto conn = ep.get_service_conn(remote); conn)
        {
            conn->conn->send_datagram(std::move(body));
            return true;
        }

        _router.loop()->call(
            [this, body = std::move(body), remote]() { connect_and_send(remote, std::nullopt, std::move(body)); });

        return false;
    }

    void LinkManager::close_connection(RouterID rid)
    {
        return ep.close_connection(rid);
    }

    void LinkManager::test_reachability(const RouterID& rid, conn_open_hook on_open, conn_closed_hook on_close)
    {
        if (auto rc = node_db->get_rc(rid))
        {
            connect_to(*rc, std::move(on_open), std::move(on_close));
        }
        else
            log::warning(quic_cat, "Could not find RouterContact for connection to rid:{}", rid);
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

            if (auto rv = ep.establish_and_send(
                    oxen::quic::RemoteAddress{router.ToView(), remote_addr},
                    *rc,
                    std::move(endpoint),
                    std::move(body),
                    std::move(func));
                rv)
            {
                log::info(quic_cat, "Begun establishing connection to {}", remote_addr);
                return;
            }

            log::warning(quic_cat, "Failed to begin establishing connection to {}", remote_addr);
        }
        else
            log::error(quic_cat, "Error: Could not find RC for connection to rid:{}, message not sent!", router);
    }

    void LinkManager::connect_to(const RemoteRC& rc, conn_open_hook on_open, conn_closed_hook on_close)
    {
        const auto& rid = rc.router_id();

        if (ep.have_service_conn(rid))
        {
            log::warning(logcat, "We already have a connection to {}!", rid);
            // TODO: should implement some connection failed logic, but not the same logic that
            // would be executed for another failure case
            return;
        }

        const auto& remote_addr = rc.addr();

        if (auto rv = ep.establish_connection(
                oxen::quic::RemoteAddress{rid.ToView(), remote_addr}, rc, std::move(on_open), std::move(on_close));
            rv)
        {
            log::info(quic_cat, "Begun establishing connection to {}", remote_addr);
            return;
        }
        log::warning(quic_cat, "Failed to begin establishing connection to {}", remote_addr);
    }

    bool LinkManager::have_connection_to(const RouterID& remote) const
    {
        return ep.have_conn(remote);
    }

    bool LinkManager::have_service_connection_to(const RouterID& remote) const
    {
        return ep.have_service_conn(remote);
    }

    bool LinkManager::have_client_connection_to(const RouterID& remote) const
    {
        return ep.have_client_conn(remote);
    }

    void LinkManager::stop()
    {
        if (is_stopping)
        {
            return;
        }

        LogInfo("stopping links");
        is_stopping = true;

        quic.reset();
    }

    void LinkManager::set_conn_persist(const RouterID& remote, llarp_time_t until)
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
    void LinkManager::check_persisting_conns(llarp_time_t)
    {
        if (is_stopping)
            return;
    }

    // TODO: this
    util::StatusObject LinkManager::extract_status() const
    {
        return {};
    }

    void LinkManager::init()
    {
        is_stopping = false;
        node_db = _router.node_db();
    }

    void LinkManager::connect_to_random(int num_conns, bool client_only)
    {
        auto filter = [this, client_only](const RemoteRC& rc) -> bool {
            const auto& rid = rc.router_id();
            auto res = client_only ? not ep.have_client_conn(rid) : not ep.have_conn(rid);

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

    void LinkManager::recv_data_message(oxen::quic::dgram_interface&, bstring)
    {
        // TODO: this
    }

    void LinkManager::gossip_rc(const RouterID& last_sender, const RemoteRC& rc)
    {
        _router.loop()->call([this, last_sender, rc]() {
            int count = 0;
            const auto& gossip_src = rc.router_id();

            for (auto& [rid, conn] : ep.service_conns)
            {
                // don't send back to the gossip source or the last sender
                if (rid == gossip_src or rid == last_sender)
                    continue;

                send_control_message(
                    rid, "gossip_rc"s, GossipRCMessage::serialize(last_sender, rc)/* , [](oxen::quic::message) {
                        log::trace(logcat, "PLACEHOLDER FOR GOSSIP RC RESPONSE HANDLER");
                    } */);
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
        RouterID src, sender;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};

            btdc.required("rc");
            rc = RemoteRC{btdc.consume_dict_data()};
            src.from_string(btdc.require<std::string>("sender"));
        }
        catch (const std::exception& e)
        {
            log::critical(link_cat, "Exception handling GossipRC request: {}", e.what());
            return;
        }

        if (node_db->verify_store_gossip_rc(rc))
        {
            log::critical(link_cat, "Received updated RC, forwarding to relay peers.");
            gossip_rc(_router.local_rid(), rc);
        }
        else
            log::debug(link_cat, "Received known or old RC, not storing or forwarding.");
    }

    // TODO: can probably use ::send_control_message instead. Need to discuss the potential
    // difference in calling Endpoint::get_service_conn vs Endpoint::get_conn
    void LinkManager::fetch_bootstrap_rcs(
        const RemoteRC& source, std::string payload, std::function<void(oxen::quic::message m)> f)
    {
        _router.loop()->call([this, source, payload, func = std::move(f)]() {
            const auto& rid = source.router_id();

            log::critical(logcat, "Dispatching bootstrap fetch request!");
            send_control_message(rid, "bfetch_rcs"s, std::move(payload), std::move(func));
        });
    }

    void LinkManager::handle_fetch_bootstrap_rcs(oxen::quic::message m)
    {
        // this handler should not be registered for clients
        assert(_router.is_service_node());
        log::critical(logcat, "Handling fetch bootstrap fetch request...");

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
            log::critical(link_cat, "Exception handling RC Fetch request (body:{}): {}", m.body(), e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        if (remote)
        {
            auto is_snode = _router.is_service_node();
            auto& rid = remote->router_id();

            if (is_snode)
            {
                // we already insert the
                auto& registered = node_db->registered_routers();

                if (auto itr = registered.find(rid); itr != registered.end())
                {
                    log::critical(
                        logcat,
                        "Bootstrap node confirmed RID:{} is registered; approving fetch request "
                        "and "
                        "saving RC!",
                        rid);
                    node_db->verify_gossip_bfetch_rc(*remote);
                }
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
        rc_time since_time;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};

            auto btlc = btdc.require<oxenc::bt_list_consumer>("explicit_ids");

            while (not btlc.is_finished())
                explicit_ids.emplace(btlc.consume<ustring_view>().data());

            since_time = rc_time{std::chrono::seconds{btdc.require<int64_t>("since")}};
        }
        catch (const std::exception& e)
        {
            log::critical(link_cat, "Exception handling RC Fetch request: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        const auto& rcs = node_db->get_rcs();

        oxenc::bt_dict_producer btdp;
        // const auto& last_time = node_db->get_last_rc_update_times();

        {
            auto sublist = btdp.append_list("rcs");

            // if since_time isn't epoch start, subtract a bit for buffer
            if (since_time != decltype(since_time)::min())
                since_time -= 5s;

            // Initial fetch: give me all the RC's
            if (explicit_ids.empty())
            {
                log::critical(logcat, "Returning ALL locally held RCs for initial FetchRC request...");
                for (const auto& rc : rcs)
                {
                    sublist.append_encoded(rc.view());
                }
            }
            else
            {
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
        }

        m.respond(std::move(btdp).str());
    }

    void LinkManager::fetch_router_ids(
        const RouterID& via, std::string payload, std::function<void(oxen::quic::message m)> func)
    {
        // this handler should not be registered for service nodes
        assert(not _router.is_service_node());

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
            source = RouterID{btdc.require<ustring_view>("source")};
        }
        catch (const std::exception& e)
        {
            log::critical(link_cat, "Error fulfilling FetchRIDs request: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        // if bad request, silently fail
        if (source.size() != RouterID::SIZE)
            return;

        if (source != local)
        {
            log::critical(logcat, "Relaying FetchRID request to intended target RID:{}", source);
            send_control_message(
                source,
                "fetch_rids"s,
                m.body_str(),
                [source_rid = std::move(source), original = std::move(m)](oxen::quic::message m) mutable {
                    original.respond(m.body_str(), m.is_error());
                });
            return;
        }

        oxenc::bt_dict_producer btdp;

        {
            auto btlp = btdp.append_list("routers");

            const auto& known_rids = node_db->get_known_rids();

            for (const auto& rid : known_rids)
                btlp.append(rid.ToView());
        }

        btdp.append_signature("signature", [this](ustring_view to_sign) {
            std::array<unsigned char, 64> sig;

            if (!crypto::sign(const_cast<unsigned char*>(sig.data()), _router.identity(), to_sign))
                throw std::runtime_error{"Failed to sign fetch RouterIDs response"};

            return sig;
        });

        log::critical(logcat, "Returning ALL locally held RIDs to FetchRIDs request!");
        m.respond(std::move(btdp).str());
    }

    void LinkManager::handle_find_name(std::string_view body, std::function<void(std::string)> respond)
    {
        std::string name_hash;

        try
        {
            oxenc::bt_dict_consumer btdp{body};

            name_hash = btdp.require<std::string>("H");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            respond(messages::ERROR_RESPONSE);
            return;
        }

        _router.rpc_client()->lookup_ons_hash(
            name_hash,
            [respond = std::move(respond)]([[maybe_unused]] std::optional<service::EncryptedName> maybe) mutable {
                if (maybe)
                    respond(serialize_response({{"NAME", maybe->ciphertext}}));
                else
                    respond(serialize_response({{messages::STATUS_KEY, FindNameMessage::NOT_FOUND}}));
            });
    }

    void LinkManager::handle_find_name_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(link_cat, "FindNameMessage request timed out!");
            return;
        }

        std::string payload;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            payload = btdc.require<std::string>(m ? "NAME" : messages::STATUS_KEY);
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
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
                log::info(link_cat, "FindNameMessage failed with unkown error!");

                // resend?
            }
            else if (payload == FindNameMessage::NOT_FOUND)
            {
                log::info(link_cat, "FindNameMessage failed with unkown error!");
                // what to do here?
            }
            else
                log::info(link_cat, "FindNameMessage failed with unkown error!");
        }
    }

    void LinkManager::handle_publish_intro(std::string_view body, std::function<void(std::string)> respond)
    {
        std::string introset, derived_signing_key, payload, sig, nonce;
        uint64_t is_relayed, relay_order;
        std::chrono::milliseconds signed_at;

        try
        {
            oxenc::bt_dict_consumer btdc_a{body};

            introset = btdc_a.require<std::string>("I");
            relay_order = btdc_a.require<uint64_t>("O");
            is_relayed = btdc_a.require<uint64_t>("R");

            oxenc::bt_dict_consumer btdc_b{introset.data()};

            derived_signing_key = btdc_b.require<std::string>("d");
            nonce = btdc_b.require<std::string>("n");
            signed_at = std::chrono::milliseconds{btdc_b.require<uint64_t>("s")};
            payload = btdc_b.require<std::string>("x");
            sig = btdc_b.require<std::string>("z");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            respond(messages::ERROR_RESPONSE);
            return;
        }

        const auto now = _router.now();
        const auto addr = dht::Key_t{reinterpret_cast<uint8_t*>(derived_signing_key.data())};
        const auto local_key = _router.rc().router_id();

        if (not service::EncryptedIntroSet::verify(introset, derived_signing_key, sig))
        {
            log::error(link_cat, "Received PublishIntroMessage with invalid introset: {}", introset);
            respond(serialize_response({{messages::STATUS_KEY, PublishIntroMessage::INVALID_INTROSET}}));
            return;
        }

        if (now + service::MAX_INTROSET_TIME_DELTA > signed_at + path::DEFAULT_LIFETIME)
        {
            log::error(link_cat, "Received PublishIntroMessage with expired introset: {}", introset);
            respond(serialize_response({{messages::STATUS_KEY, PublishIntroMessage::EXPIRED}}));
            return;
        }

        auto closest_rcs = _router.node_db()->find_many_closest_to(addr, INTROSET_STORAGE_REDUNDANCY);

        if (closest_rcs.size() != INTROSET_STORAGE_REDUNDANCY)
        {
            log::error(link_cat, "Received PublishIntroMessage but only know {} nodes", closest_rcs.size());
            respond(serialize_response({{messages::STATUS_KEY, PublishIntroMessage::INSUFFICIENT}}));
            return;
        }

        service::EncryptedIntroSet enc{derived_signing_key, signed_at, payload, nonce, sig};

        if (is_relayed)
        {
            if (relay_order >= INTROSET_STORAGE_REDUNDANCY)
            {
                log::error(link_cat, "Received PublishIntroMessage with invalide relay order: {}", relay_order);
                respond(serialize_response({{messages::STATUS_KEY, PublishIntroMessage::INVALID_ORDER}}));
                return;
            }

            log::info(link_cat, "Relaying PublishIntroMessage for {}", addr);

            const auto& peer_rc = closest_rcs[relay_order];
            const auto& peer_key = peer_rc.router_id();

            if (peer_key == local_key)
            {
                log::info(
                    link_cat,
                    "Received PublishIntroMessage in which we are peer index {}.. storing introset",
                    relay_order);

                _router.contacts().put_intro(std::move(enc));
                respond(serialize_response({{messages::STATUS_KEY, ""}}));
            }
            else
            {
                log::info(link_cat, "Received PublishIntroMessage; propagating to peer index {}", relay_order);

                send_control_message(
                    peer_key,
                    "publish_intro",
                    PublishIntroMessage::serialize(introset, relay_order, is_relayed),
                    [respond = std::move(respond)](oxen::quic::message m) {
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
            log::info(link_cat, "Received PublishIntroMessage for {} (TXID: {}); we are candidate {}");

            _router.contacts().put_intro(std::move(enc));
            respond(serialize_response({{messages::STATUS_KEY, ""}}));
        }
        else
            log::warning(link_cat, "Received non-relayed PublishIntroMessage from {}; we are not the candidate", addr);
    }

    // DISCUSS: I feel like ::handle_publish_intro_response should be the callback that handles the
    // response to a relayed publish_intro (above line 1131-ish)

    void LinkManager::handle_publish_intro_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(link_cat, "PublishIntroMessage timed out!");
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
            log::warning(link_cat, "Exception: {}", e.what());
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
                log::info(link_cat, "PublishIntroMessage failed with remote exception!");
                // Do something smart here probably
                return;
            }

            log::info(link_cat, "PublishIntroMessage failed with error code: {}", payload);

            if (payload == PublishIntroMessage::INVALID_INTROSET)
            {}
            else if (payload == PublishIntroMessage::EXPIRED)
            {}
            else if (payload == PublishIntroMessage::INSUFFICIENT)
            {}
            else if (payload == PublishIntroMessage::INVALID_ORDER)
            {}
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
            log::warning(link_cat, "Exception: {}", e.what());
            respond(messages::ERROR_RESPONSE);
            return;
        }

        const auto addr = dht::Key_t{location.data()};

        if (is_relayed)
        {
            if (relay_order >= INTROSET_STORAGE_REDUNDANCY)
            {
                log::warning(link_cat, "Received FindIntroMessage with invalid relay order: {}", relay_order);
                respond(serialize_response({{messages::STATUS_KEY, FindIntroMessage::INVALID_ORDER}}));
                return;
            }

            auto closest_rcs = _router.node_db()->find_many_closest_to(addr, INTROSET_STORAGE_REDUNDANCY);

            if (closest_rcs.size() != INTROSET_STORAGE_REDUNDANCY)
            {
                log::error(link_cat, "Received FindIntroMessage but only know {} nodes", closest_rcs.size());
                respond(serialize_response({{messages::STATUS_KEY, FindIntroMessage::INSUFFICIENT_NODES}}));
                return;
            }

            log::info(link_cat, "Relaying FindIntroMessage for {}", addr);

            const auto& peer_rc = closest_rcs[relay_order];
            const auto& peer_key = peer_rc.router_id();

            send_control_message(
                peer_key,
                "find_intro",
                FindIntroMessage::serialize(dht::Key_t{peer_key}, is_relayed, relay_order),
                [respond = std::move(respond)](oxen::quic::message relay_response) mutable {
                    if (relay_response)
                        log::info(
                            link_cat,
                            "Relayed FindIntroMessage returned successful response; transmitting "
                            "to initial "
                            "requester");
                    else if (relay_response.timed_out)
                        log::critical(link_cat, "Relayed FindIntroMessage timed out! Notifying initial requester");
                    else
                        log::critical(link_cat, "Relayed FindIntroMessage failed! Notifying initial requester");

                    respond(relay_response.body_str());
                });
        }
        else
        {
            if (auto maybe_intro = _router.contacts().get_introset_by_location(addr))
                respond(serialize_response({{"INTROSET", maybe_intro->bt_encode()}}));
            else
            {
                log::warning(link_cat, "Received FindIntroMessage with relayed == false and no local introset entry");
                respond(serialize_response({{messages::STATUS_KEY, FindIntroMessage::NOT_FOUND}}));
            }
        }
    }

    void LinkManager::handle_find_intro_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(link_cat, "FindIntroMessage timed out!");
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
            log::warning(link_cat, "Exception: {}", e.what());
            return;
        }

        // success case, neither timed out nor errored
        if (m)
        {
            service::EncryptedIntroSet enc{payload};
            _router.contacts().put_intro(std::move(enc));
        }
        else
        {
            log::info(link_cat, "FindIntroMessage failed with error: {}", payload);
            // Do something smart here probably
        }
    }

    void LinkManager::handle_path_build(oxen::quic::message m, const RouterID& from)
    {
        if (!_router.path_context().is_transit_allowed())
        {
            log::warning(link_cat, "got path build request when not permitting transit");
            m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::NO_TRANSIT}}), true);
            return;
        }

        try
        {
            auto payload_list = oxenc::bt_deserialize<std::deque<ustring>>(m.body());
            if (payload_list.size() != path::MAX_LEN)
            {
                log::info(link_cat, "Path build message with wrong number of frames");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_FRAMES}}), true);
                return;
            }

            oxenc::bt_dict_consumer frame_info{payload_list.front()};
            auto frame = frame_info.require<ustring>("FRAME");
            auto hash = frame_info.require<ustring>("HASH");

            oxenc::bt_dict_consumer hop_dict{frame};
            auto hop_payload = hop_dict.require<ustring>("ENCRYPTED");
            auto outer_nonce = hop_dict.require<ustring>("NONCE");
            auto other_pubkey = hop_dict.require<ustring>("PUBKEY");

            SharedSecret shared;
            // derive shared secret using ephemeral pubkey and our secret key (and nonce)
            if (!crypto::dh_server(shared.data(), other_pubkey.data(), _router.pubkey(), outer_nonce.data()))
            {
                log::info(link_cat, "DH server initialization failed during path build");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_CRYPTO}}), true);
                return;
            }

            // hash data and check against given hash
            ShortHash digest;
            if (!crypto::hmac(digest.data(), frame.data(), frame.size(), shared))
            {
                log::error(link_cat, "HMAC failed on path build request");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_CRYPTO}}), true);
                return;
            }
            if (!std::equal(digest.begin(), digest.end(), hash.data()))
            {
                log::info(link_cat, "HMAC mismatch on path build request");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_CRYPTO}}), true);
                return;
            }

            // decrypt frame with our hop info
            if (!crypto::xchacha20(hop_payload.data(), hop_payload.size(), shared.data(), outer_nonce.data()))
            {
                log::info(link_cat, "Decrypt failed on path build request");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_CRYPTO}}), true);
                return;
            }

            oxenc::bt_dict_consumer hop_info{hop_payload};
            auto commkey = hop_info.require<std::string>("COMMKEY");
            auto lifetime = hop_info.require<uint64_t>("LIFETIME");
            auto inner_nonce = hop_info.require<ustring>("NONCE");
            auto rx_id = hop_info.require<std::string>("RX");
            auto tx_id = hop_info.require<std::string>("TX");
            auto upstream = hop_info.require<std::string>("UPSTREAM");

            // populate transit hop object with hop info
            // TODO: IP / path build limiting clients
            auto hop = std::make_shared<path::TransitHop>();
            hop->info.downstream = from;

            // extract pathIDs and check if zero or used
            hop->info.txID.from_string(tx_id);
            hop->info.rxID.from_string(rx_id);

            if (hop->info.txID.IsZero() || hop->info.rxID.IsZero())
            {
                log::warning(link_cat, "Invalid PathID; PathIDs must be non-zero");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_PATHID}}), true);
                return;
            }

            hop->info.upstream.from_string(upstream);

            if (_router.path_context().has_transit_hop(hop->info))
            {
                log::warning(link_cat, "Invalid PathID; PathIDs must be unique");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_PATHID}}), true);
                return;
            }

            if (!crypto::dh_server(hop->pathKey.data(), other_pubkey.data(), _router.pubkey(), inner_nonce.data()))
            {
                log::warning(link_cat, "DH failed during path build.");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_CRYPTO}}), true);
                return;
            }
            // generate hash of hop key for nonce mutation
            ShortHash xor_hash;
            crypto::shorthash(xor_hash, hop->pathKey.data(), hop->pathKey.size());
            hop->nonceXOR = xor_hash.data();  // nonceXOR is 24 bytes, ShortHash is 32; this will truncate

            // set and check path lifetime
            hop->lifetime = 1ms * lifetime;

            if (hop->lifetime >= path::DEFAULT_LIFETIME)
            {
                log::warning(link_cat, "Path build attempt with too long of a lifetime.");
                m.respond(serialize_response({{messages::STATUS_KEY, PathBuildMessage::BAD_LIFETIME}}), true);
                return;
            }

            hop->started = _router.now();
            _router.persist_connection_until(hop->info.downstream, hop->ExpireTime() + 10s);

            if (hop->info.upstream == _router.pubkey())
            {
                hop->terminal_hop = true;
                // we are terminal hop and everything is okay
                _router.path_context().put_transit_hop(hop);
                m.respond(messages::OK_RESPONSE, false);
                return;
            }

            // pop our frame, to be randomized after onion step and appended
            auto end_frame = std::move(payload_list.front());
            payload_list.pop_front();
            auto onion_nonce = SymmNonce{inner_nonce.data()} ^ hop->nonceXOR;
            // (de-)onion each further frame using the established shared secret and
            // onion_nonce = inner_nonce ^ nonceXOR
            // Note: final value passed to crypto::onion is xor factor, but that's for *after* the
            // onion round to compute the return value, so we don't care about it.
            for (auto& element : payload_list)
            {
                crypto::onion(element.data(), element.size(), hop->pathKey, onion_nonce, onion_nonce);
            }
            // randomize final frame.  could probably paste our frame on the end and onion it with
            // the rest, but it gains nothing over random.
            randombytes(end_frame.data(), end_frame.size());
            payload_list.push_back(std::move(end_frame));

            send_control_message(
                hop->info.upstream,
                "path_build",
                oxenc::bt_serialize(payload_list),
                [hop, this, prev_message = std::move(m)](oxen::quic::message m) {
                    if (m)
                    {
                        log::info(
                            link_cat,
                            "Upstream returned successful path build response; giving hop info to "
                            "Router, "
                            "then relaying response");
                        _router.path_context().put_transit_hop(hop);
                    }
                    if (m.timed_out)
                        log::info(link_cat, "Upstream timed out on path build; relaying timeout");
                    else
                        log::info(link_cat, "Upstream returned path build failure; relaying response");

                    m.respond(m.body_str(), m.is_error());
                });
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
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
            log::warning(link_cat, "Exception: {}", e.what());
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
            log::warning(link_cat, "Exception: {}", e.what());
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
            log::warning(link_cat, "Exception: {}", e.what());
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
            log::warning(link_cat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }
    }

    void LinkManager::handle_obtain_exit(oxen::quic::message m)
    {
        uint64_t flag;
        ustring_view pubkey, sig;
        std::string_view tx_id, dict_data;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();
            oxenc::bt_dict_consumer btdc{dict_data};

            sig = to_usv(btlc.consume_string_view());
            flag = btdc.require<uint64_t>("E");
            pubkey = btdc.require<ustring_view>("I");
            tx_id = btdc.require<std::string_view>("T");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            throw;
        }

        RouterID target{pubkey.data()};
        auto transit_hop = _router.path_context().GetTransitHop(target, PathID_t{to_usv(tx_id).data()});

        const auto rx_id = transit_hop->info.rxID;

        auto success =
            (crypto::verify(pubkey, to_usv(dict_data), sig)
             and _router.exitContext().obtain_new_exit(PubKey{pubkey.data()}, rx_id, flag != 0));

        m.respond(ObtainExitMessage::sign_and_serialize_response(_router.identity(), tx_id), not success);
    }

    void LinkManager::handle_obtain_exit_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(link_cat, "ObtainExitMessage timed out!");
            return;
        }
        if (m.is_error())
        {
            // TODO: what to do here
        }

        std::string_view tx_id, dict_data;
        ustring_view sig;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();
            oxenc::bt_dict_consumer btdc{dict_data};

            sig = to_usv(btlc.consume_string_view());
            tx_id = btdc.require<std::string_view>("T");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            throw;
        }

        auto path_ptr = _router.path_context().get_path(PathID_t{to_usv(tx_id).data()});

        if (crypto::verify(_router.pubkey(), to_usv(dict_data), sig))
            path_ptr->enable_exit_traffic();
    }

    void LinkManager::handle_update_exit(oxen::quic::message m)
    {
        std::string_view path_id, tx_id, dict_data;
        ustring_view sig;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();
            oxenc::bt_dict_consumer btdc{dict_data};

            sig = to_usv(btlc.consume_string_view());
            path_id = btdc.require<std::string_view>("P");
            tx_id = btdc.require<std::string_view>("T");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        auto transit_hop = _router.path_context().GetTransitHop(_router.pubkey(), PathID_t{to_usv(tx_id).data()});

        if (auto exit_ep = _router.exitContext().find_endpoint_for_path(PathID_t{to_usv(path_id).data()}))
        {
            if (crypto::verify(exit_ep->PubKey().data(), to_usv(dict_data), sig))
            {
                (exit_ep->UpdateLocalPath(transit_hop->info.rxID))
                    ? m.respond(UpdateExitMessage::sign_and_serialize_response(_router.identity(), tx_id))
                    : m.respond(serialize_response({{messages::STATUS_KEY, UpdateExitMessage::UPDATE_FAILED}}), true);
            }
            // If we fail to verify the message, no-op
        }
    }

    void LinkManager::handle_update_exit_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(link_cat, "UpdateExitMessage timed out!");
            return;
        }
        if (m.is_error())
        {
            // TODO: what to do here
        }

        std::string tx_id;
        std::string_view dict_data;
        ustring_view sig;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();
            oxenc::bt_dict_consumer btdc{dict_data};

            sig = to_usv(btlc.consume_string_view());
            tx_id = btdc.require<std::string_view>("T");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            return;
        }

        auto path_ptr = _router.path_context().get_path(PathID_t{to_usv(tx_id).data()});

        if (crypto::verify(_router.pubkey(), to_usv(dict_data), sig))
        {
            if (path_ptr->update_exit(std::stoul(tx_id)))
            {
                // TODO: talk to tom and Jason about how this stupid shit was a no-op originally
                // see Path::HandleUpdateExitVerifyMessage
            }
            else
            {}
        }
    }

    void LinkManager::handle_close_exit(oxen::quic::message m)
    {
        std::string_view tx_id, dict_data;
        ustring_view sig;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();
            oxenc::bt_dict_consumer btdc{dict_data};

            sig = to_usv(btlc.consume_string_view());
            tx_id = btdc.require<std::string_view>("T");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            m.respond(messages::ERROR_RESPONSE, true);
            return;
        }

        auto transit_hop = _router.path_context().GetTransitHop(_router.pubkey(), PathID_t{to_usv(tx_id).data()});

        const auto rx_id = transit_hop->info.rxID;

        if (auto exit_ep = router().exitContext().find_endpoint_for_path(rx_id))
        {
            if (crypto::verify(exit_ep->PubKey().data(), to_usv(dict_data), sig))
            {
                exit_ep->Close();
                m.respond(CloseExitMessage::sign_and_serialize_response(_router.identity(), tx_id));
            }
        }

        m.respond(serialize_response({{messages::STATUS_KEY, CloseExitMessage::UPDATE_FAILED}}), true);
    }

    void LinkManager::handle_close_exit_response(oxen::quic::message m)
    {
        if (m.timed_out)
        {
            log::info(link_cat, "CloseExitMessage timed out!");
            return;
        }
        if (m.is_error())
        {
            // TODO: what to do here
        }

        std::string_view nonce, tx_id, dict_data;
        ustring_view sig;

        try
        {
            oxenc::bt_list_consumer btlc{m.body()};
            dict_data = btlc.consume_dict_data();
            oxenc::bt_dict_consumer btdc{dict_data};

            sig = to_usv(btlc.consume_string_view());
            tx_id = btdc.require<std::string_view>("T");
            nonce = btdc.require<std::string_view>("Y");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            return;
        }

        auto path_ptr = _router.path_context().get_path(PathID_t{to_usv(tx_id).data()});

        if (path_ptr->SupportsAnyRoles(path::ePathRoleExit | path::ePathRoleSVC)
            and crypto::verify(_router.pubkey(), to_usv(dict_data), sig))
            path_ptr->mark_exit_closed();
    }

    void LinkManager::handle_path_control(oxen::quic::message m, const RouterID& from)
    {
        ustring_view nonce, path_id_str;
        std::string payload;

        try
        {
            oxenc::bt_dict_consumer btdc{m.body()};
            nonce = btdc.require<ustring_view>("NONCE");
            path_id_str = btdc.require<ustring_view>("PATHID");
            payload = btdc.require<std::string>("PAYLOAD");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            return;
        }

        auto symnonce = SymmNonce{nonce.data()};
        auto path_id = PathID_t{path_id_str.data()};
        auto hop = _router.path_context().GetTransitHop(from, path_id);

        // TODO: use "path_control" for both directions?  If not, drop message on
        // floor if we don't have the path_id in question; if we decide to make this
        // bidirectional, will need to check if we have a Path with path_id.
        if (not hop)
            return;

        // if terminal hop, payload should contain a request (e.g. "find_name"); handle and respond.
        if (hop->terminal_hop)
        {
            hop->onion(payload, symnonce, false);
            handle_inner_request(std::move(m), std::move(payload), std::move(hop));
            return;
        }

        auto& next_id = path_id == hop->info.rxID ? hop->info.txID : hop->info.rxID;
        auto& next_router = path_id == hop->info.rxID ? hop->info.upstream : hop->info.downstream;

        std::string new_payload = hop->onion_and_payload(payload, next_id, symnonce);

        send_control_message(
            next_router,
            "path_control"s,
            std::move(new_payload),
            [hop_weak = hop->weak_from_this(), path_id, prev_message = std::move(m)](
                oxen::quic::message response) mutable {
                auto hop = hop_weak.lock();

                if (not hop)
                    return;

                ustring_view nonce;
                std::string payload, response_body;

                try
                {
                    oxenc::bt_dict_consumer btdc{response.body()};
                    nonce = btdc.require<ustring_view>("NONCE");
                    payload = btdc.require<std::string>("PAYLOAD");
                }
                catch (const std::exception& e)
                {
                    log::warning(link_cat, "Exception: {}", e.what());
                    return;
                }

                auto symnonce = SymmNonce{nonce.data()};
                auto resp_payload = hop->onion_and_payload(payload, path_id, symnonce);
                prev_message.respond(std::move(resp_payload), false);
            });
    }

    void LinkManager::handle_inner_request(
        oxen::quic::message m, std::string payload, std::shared_ptr<path::TransitHop> hop)
    {
        std::string_view body, method;

        try
        {
            oxenc::bt_dict_consumer btdc{payload};
            body = btdc.require<std::string_view>("BODY");
            method = btdc.require<std::string_view>("METHOD");
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            return;
        }

        // If a handler exists for "method", call it; else drop request on the floor.
        auto itr = path_requests.find(method);

        if (itr == path_requests.end())
        {
            log::info(link_cat, "Received path control request \"{}\", which has no handler.", method);
            return;
        }

        auto respond = [m = std::move(m), hop_weak = hop->weak_from_this()](std::string response) mutable {
            auto hop = hop_weak.lock();
            if (not hop)
                return;  // transit hop gone, drop response

            m.respond(hop->onion_and_payload(response, hop->info.rxID), false);
        };

        std::invoke(itr->second, this, std::move(body), std::move(respond));
    }

    void LinkManager::handle_convo_intro(oxen::quic::message m)
    {
        if (not m)
        {
            log::info(link_cat, "Path control message timed out!");
            return;
        }

        try
        {
            //
        }
        catch (const std::exception& e)
        {
            log::warning(link_cat, "Exception: {}", e.what());
            return;
        }
    }

}  // namespace llarp
