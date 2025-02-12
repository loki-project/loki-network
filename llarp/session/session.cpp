#include "session.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/handlers/session.hpp>
#include <llarp/link/tunnel.hpp>
#include <llarp/messages/dht.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/messages/session.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/formattable.hpp>

#include <utility>

namespace llarp::session
{
    static auto logcat = log::Cat("session");

    BaseSession::BaseSession(
        Router& r,
        std::shared_ptr<path::Path> _p,
        handlers::SessionEndpoint& parent,
        NetworkAddress remote,
        HopID remote_pivot_txid,
        session_tag _t,
        bool use_tun,
        bool is_outbound,
        std::optional<shared_kx_data> kx_data)
        : _r{r},
          _parent{parent},
          _tag{std::move(_t)},
          _remote{std::move(remote)},
          session_keys{std::move(kx_data)},
          _remote_pivot_txid{std::move(remote_pivot_txid)},
          _use_tun{use_tun},
          _is_outbound{is_outbound},
          _is_snode_session{_is_outbound ? !_remote.is_client() : r.is_service_node()},
          _is_exit_session{session_keys.has_value() && !_is_snode_session}
    {
        set_new_current_path(std::move(_p));

        if (_use_tun)
            _recv_dgram = [this](std::vector<uint8_t> data) {
                _r.tun_endpoint()->handle_inbound_packet(IPPacket{std::move(data)}, _tag, _remote);
            };
        else
            _recv_dgram = [this](std::vector<uint8_t> data) {
                _ep->manually_receive_packet(
                    NetworkPacket{oxen::quic::Path{}, bstring{reinterpret_cast<std::byte*>(data.data()), data.size()}});
            };
    }

    bool BaseSession::send_path_control_message(std::string method, std::string body, bt_control_response_hook func)
    {
        auto inner_payload = PATH::CONTROL::serialize(std::move(method), std::move(body));

        auto pivot_payload =
            ONION::serialize_hop(_remote_pivot_txid.to_view(), SymmNonce::make_random(), std::move(inner_payload));
        auto intermediate_payload = PATH::CONTROL::serialize("path_control", std::move(pivot_payload));

        return _current_path->send_path_control_message("path_control", intermediate_payload, std::move(func));
    }

    bool BaseSession::send_path_data_message(std::string data)
    {
        if (session_keys.has_value())
            session_keys->encrypt(data);

        auto inner_payload = PATH::DATA::serialize_inner(std::move(data), _tag);

        auto intermediate_payload = PATH::DATA::serialize_intermediate(std::move(inner_payload), _remote_pivot_txid);
        return _r.send_data_message(
            _current_path->upstream_rid(), _current_path->make_path_message(std::move(intermediate_payload)));
    }

    void BaseSession::recv_path_data_message(std::vector<uint8_t> data)
    {
        if (session_keys.has_value())
            session_keys->decrypt(data);

        if (_recv_dgram)
            _recv_dgram(std::move(data));
        else
            throw std::runtime_error{"Session does not have hook to receive datagrams!"};
    }

    void BaseSession::set_new_current_path(std::shared_ptr<path::Path> _new_path)
    {
        if (_current_path)
            _current_path->unlink_session(_tag);

        _current_path = std::move(_new_path);
        _pivot_txid = _current_path->pivot_txid();

        _current_path->link_session(_tag);
        assert(_current_path->is_linked());
    }

    void recv_path_switch2(HopID new_remote_txid, HopID new_local_txid)
    {
        log::debug(
            logcat,
            "Received new remote and local pivot txIDs [ remote:{} | local:{} ]",
            new_remote_txid,
            new_local_txid);
    }

    void BaseSession::recv_path_switch(HopID new_remote_txid)
    {
        log::debug(
            logcat,
            "Received new pivot txID from remote ({}) [ old:{} | new:{} ] ",
            _remote,
            _remote_pivot_txid,
            new_remote_txid);
        _remote_pivot_txid = new_remote_txid;
    }

    void BaseSession::publish_client_contact(const EncryptedClientContact& ecc, bt_control_response_hook func)
    {
        send_path_control_message(
            "publish_cc", PublishClientContact::serialize(std::move(ecc), _r.local_rid()), std::move(func));
    }

    void BaseSession::_init_ep()
    {
        _ep = _r.quic_tunnel()->net()->endpoint(
            LOCALHOST_BLANK, oxen::quic::opt::manual_routing{[this](const oxen::quic::Path&, bstring_view data) {
                send_path_data_message(std::string{reinterpret_cast<const char*>(data.data()), data.size()});
            }});
    }

    void BaseSession::tcp_backend_connect()
    {
        _init_ep();

        // TODO: change the libquic address to the lokinet-primary-ip:port (or just the ip)
        auto _handle = TCPHandle::make_client(_r.loop(), oxen::quic::Address{});

        _ep->listen(
            _r.quic_tunnel()->creds(),
            [this](oxen::quic::connection_interface& ci) {
                if (not _ci)
                    _ci = ci.shared_from_this();
                else
                    log::warning(logcat, "Tunneled QUIC endpoint can only have one connection per remote!");
            },
            [this, h = _handle](oxen::quic::Stream& s) {
                // On stream creation, the call to ::connect(...) will:
                //  - create a bufferevent
                //  - set the recv_data_cb in the Stream to write to that bufferevent
                //  - make a TCP connection over the bufferevent to lokinet-primary-ip:port
                auto tcp_conn = h->connect(s.shared_from_this());
                _tcp_conns.insert(std::move(tcp_conn));
                return 0;
            });

        _handles.emplace(_handle->port(), std::move(_handle));
    }

    void BaseSession::tcp_backend_listen(on_session_init_hook cb, uint16_t port)
    {
        _init_ep();

        auto _handle = TCPHandle::make_server(
            _r.loop(),
            [this](struct bufferevent* _bev, evutil_socket_t _fd) mutable {
                auto s = _ci->open_stream<oxen::quic::Stream>([_bev](oxen::quic::Stream& s, bstring_view data) {
                    auto rv = bufferevent_write(_bev, data.data(), data.size());

                    log::info(
                        logcat,
                        "Stream (id:{}) {} {}B to TCP buffer",
                        s.stream_id(),
                        rv < 0 ? "failed to write" : "successfully wrote",
                        data.size());
                });

                auto tcp_conn = std::make_shared<TCPConnection>(_bev, _fd, std::move(s));

                auto [itr, b] = _tcp_conns.insert(std::move(tcp_conn));

                return itr->get();
            },
            port);

        auto bind = _handle->bind();

        if (not bind.has_value())
            throw std::runtime_error{"Failed to bind TCP listener!"};

        _handles.emplace(_handle->port(), std::move(_handle));

        _ci = _ep->connect(
            KeyedAddress{TUNNEL_PUBKEY},
            _r.quic_tunnel()->creds(),
            [addr = *bind, hook = std::move(cb)](oxen::quic::connection_interface&) { hook(addr.to_ipv4()); },
            [](oxen::quic::connection_interface&, uint64_t) {
                // TESTNET: TODO:
            });
    }

    void BaseSession::set_new_tag(const session_tag& tag) { _tag = tag; }

    void BaseSession::activate()
    {
        _is_active = true;
        log::debug(logcat, "Session to remote ({}) activated!", _remote);
    }

    void BaseSession::deactivate()
    {
        _is_active = false;
        log::debug(logcat, "Session to remote ({}) deactivated!", _remote);
    }

    void BaseSession::stop_session(bool send_close, bt_control_response_hook func)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (send_close)
        {
            std::promise<void> prom;

            _r.loop()->call([&]() mutable {
                send_path_close(std::move(func));
                prom.set_value();
            });

            prom.get_future().get();
            log::debug(logcat, "Dispatched path close message!");
        }
    }

    void BaseSession::send_path_close(bt_control_response_hook func)
    {
        if (not func)
            func = [remote = _remote](oxen::quic::message m) mutable {
                log::debug(logcat, "Remote ({}) {} session", remote, m ? "successfully closed" : "failed to close");
            };

        log::debug(logcat, "Dispatching close session message...");
        send_path_control_message("session_close", CloseSession::serialize(_tag), std::move(func));
    }

    std::string BaseSession::to_string() const
    {
        return "{}BSession:[ active:{} | exit:{} | {} ]"_format(
            detail::bool_alpha(_is_outbound, "O", "I"),
            detail::bool_alpha(_is_active),
            detail::bool_alpha(_is_exit_session),
            _current_path->to_string());
    }

    OutboundSession::OutboundSession(
        NetworkAddress remote,
        handlers::SessionEndpoint& parent,
        std::shared_ptr<path::Path> path,
        HopID remote_pivot_txid,
        session_tag _t,
        intro_set _remote_intros,
        std::optional<shared_kx_data> kx_data)
        : PathHandler{parent._router, path::DEFAULT_PATHS_HELD},
          BaseSession{
              _router,
              std::move(path),
              parent,
              std::move(remote),
              std::move(remote_pivot_txid),
              std::move(_t),
              _router.using_tun_if(),
              true,
              std::move(kx_data)},
          _last_use{_router.now()}
    {
        // These can both be false but CANNOT both be true
        if (_is_exit_session and _is_snode_session)
            throw std::runtime_error{"Cannot create OutboundSession for a remote exit and remote service!"};

        add_path(_current_path);
        populate_intro_map(std::move(_remote_intros));
    }

    OutboundSession::~OutboundSession() = default;

    void OutboundSession::populate_intro_map(intro_set&& _remote_intros)
    {
        log::trace(logcat, "Populating intro map for {} intros!", _remote_intros.size());
        Lock_t l(paths_mutex);

        intro_path_mapping.clear();

        for (auto& intro : _remote_intros)
        {
            log::critical(logcat, "intro: {}", intro);
            if (intro.pivot_txid == _remote_pivot_txid)
                intro_path_mapping.emplace(intro, path::PathPtrSet{_current_path});
            else
                intro_path_mapping.emplace(intro, path::PathPtrSet{});
        }
    }

    void OutboundSession::send_path_switch(std::shared_ptr<path::Path> _new_path)
    {
        set_new_current_path(std::move(_new_path));
        path_build_succeeded(_current_path);

        log::debug(logcat, "Dispatching path-switch request to remote ({})", _remote);
        send_path_control_message(
            "path_switch",
            SessionPathSwitch::serialize(_tag, _current_path->pivot_txid(), _remote_pivot_txid),
            [](oxen::quic::message m) {
                if (m)
                    log::info(logcat, "Session path switch was successful!");
                else
                    log::warning(logcat, "Session path switch {}!", m.timed_out ? "timed out" : "failed");
            });
    }

    void OutboundSession::update_remote_intros(intro_set&& intros)
    {
        log::debug(logcat, "Updating ClientIntros for OutboundSession to remote: {}", _remote);
        /**
            - Clear intro_path_map
            - Check path_handler map for any paths to the new intro_set pivots
                - If so:
                    - add to new intro_path_map
                    - make new current path
                - Else:
                    - build and switch
         */

        populate_intro_map(std::move(intros));
        update_local_paths();
    }

    void OutboundSession::update_local_paths()
    {
        Lock_t l(paths_mutex);

        for (auto it = _paths.begin(); it != _paths.end();)
        {
            bool keep_path = false;
            auto remote_pivot = it->second->pivot_rid();

            for (auto& [intro, pathset] : intro_path_mapping)
            {
                if (intro.pivot_rid == remote_pivot)
                {
                    pathset.emplace(it->second);
                    keep_path = true;
                    break;
                }
            }

            if (keep_path)
                ++it;
            else
            {
                _router.path_context()->drop_path(it->second);
                it = _paths.erase(it);
            }
        }

        // If any of our current paths are valid to the new intros, _paths will NOT be empty. Since we
        // cleared the intro_path_map before populating it again
        if (not _paths.empty())
        {
        }
    }

    void OutboundSession::path_died([[maybe_unused]] std::shared_ptr<path::Path> p)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);
        // p->rebuild();
    }

    nlohmann::json OutboundSession::ExtractStatus() const
    {
        auto obj = path::PathHandler::ExtractStatus();
        obj["lastExitUse"] = to_json(_last_use);
        // auto pub = _auth->session_key().to_pubkey();
        // obj["exitIdentity"] = pub.to_string();
        obj["endpoint"] = _remote.to_string();
        return obj;
    }

    void OutboundSession::map_path(const std::shared_ptr<path::Path>& p)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        for (auto& [intro, pathset] : intro_path_mapping)
        {
            if (intro.pivot_rid == p->pivot_rid())
            {
                pathset.emplace(p);
                log::debug(logcat, "Client intro {} has {} paths to remote pivot", intro, pathset.size());
                return;
            }
        }

        log::warning(logcat, "Could not match currently held intros to path over pivot ({})", p->pivot_rid());
    }

    void OutboundSession::unmap_path(const std::shared_ptr<path::Path>& p)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        for (auto& [intro, pathset] : intro_path_mapping)
        {
            if (intro.pivot_rid == p->pivot_rid())
            {
                pathset.erase(p);
                log::debug(logcat, "Client intro {} has {} paths to remote pivot", intro, pathset.size());
                return;
            }
        }

        log::warning(logcat, "Could not match currently held intros to path over pivot ({})", p->pivot_rid());
    }

    void OutboundSession::path_build_succeeded(std::shared_ptr<path::Path> p)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        Lock_t l(paths_mutex);

        map_path(p);
        path::PathHandler::path_build_succeeded(p);
    }

    void OutboundSession::path_build_failed(std::shared_ptr<path::Path> p, bool timeout)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        Lock_t l(paths_mutex);

        unmap_path(p);
        path::PathHandler::path_build_failed(p, timeout);
    }

    void OutboundSession::stop_session(bool send_close, bt_control_response_hook func)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _running = false;
        BaseSession::stop_session(send_close, std::move(func));

        intro_path_mapping.clear();
        path::PathHandler::stop();
    }

    bool OutboundSession::stop(bool send_close)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _running = false;

        if (send_close)
        {
            std::promise<void> prom;

            _router.loop()->call([&]() mutable {
                send_path_close();
                prom.set_value();
            });

            prom.get_future().get();
            log::debug(logcat, "Dispatched path close message!");
        }

        intro_path_mapping.clear();

        // base class dtor clears path map and doesn't send path closes
        return path::PathHandler::stop();
    }

    void OutboundSession::build_more(size_t n)
    {
        size_t count{0};

        log::critical(
            logcat,
            "OutboundSession building {} paths to have a minimum of {} ({} intros held)",
            n,
            path::DEFAULT_PATHS_HELD,
            intro_path_mapping.size());

        for (auto& [intro, pathset] : intro_path_mapping)
        {
            if (pathset.size() >= PATHS_PER_INTRO)
            {
                log::trace(
                    logcat, "OutboundSession already holds {} paths for intro to pivot {}", pathset.size(), intro);
                continue;
            }

            auto needed = PATHS_PER_INTRO - pathset.size();
            for (size_t i = 0; i < needed; ++i)
                count += build_path_aligned_to_remote(intro.pivot_rid);

            log::trace(
                logcat,
                "OutboundSession built {} path(s) to have {} for intro to pivot {}",
                needed,
                PATHS_PER_INTRO,
                intro);

            if (count >= n)
                break;
        }

        if (count >= n)
            log::debug(logcat, "OutboundSession successfully initiated {} path-builds", count);
        else
            log::warning(logcat, "OutboundSession only initiated {} path-builds (needed: {})", count, n);
    }

    void OutboundSession::build_and_switch_paths()
    {
        auto& [intro, pathset] = *intro_path_mapping.begin();

        if (auto maybe_hops = aligned_hops_to_remote(intro.pivot_rid, {}, false))
        {
            if (auto new_path = build1(*maybe_hops))
            {
                auto payload = build2(new_path);
                auto upstream = new_path->upstream_rid();

                if (not build3(
                        std::move(upstream),
                        std::move(payload),
                        [this, new_path, remote_pivot_txid = intro.pivot_txid](oxen::quic::message m) mutable {
                            if (m)
                            {
                                log::info(logcat, "PATH ESTABLISHED: {}", new_path->hop_string());
                                _remote_pivot_txid = remote_pivot_txid;
                                // set_new_current_path(new_path);
                                // path_build_succeeded();
                                return send_path_switch(std::move(new_path));
                            }

                            try
                            {
                                if (m.timed_out)
                                {
                                    log::warning(logcat, "Path build request timed out!");
                                }
                                else
                                {
                                    oxenc::bt_dict_consumer d{m.body()};
                                    auto status = d.require<std::string_view>(messages::STATUS_KEY);
                                    log::warning(logcat, "Path build returned failure status: {}", status);
                                }
                            }
                            catch (const std::exception& e)
                            {
                                log::warning(
                                    logcat,
                                    "Exception caught parsing path build response: {}; input: {}",
                                    e.what(),
                                    m.body());
                            }

                            path_build_failed(std::move(new_path), m.timed_out);
                        }))
                {
                    log::warning(logcat, "Error sending path_build control message");
                    path_build_failed(new_path);
                }
            }
            else
            {
            }
        }
        else
            log::warning(logcat, "Failed to get hops for path-build to new pivot {}", intro.pivot_rid);
    }

    std::shared_ptr<path::Path> OutboundSession::build1(std::vector<RemoteRC>& hops)
    {
        auto path = std::make_shared<path::Path>(_router, hops, get_weak(), true, _remote.is_client());

        {
            Lock_t l{paths_mutex};

            if (auto [it, b] = _paths.try_emplace(path->upstream_rxid(), nullptr); not b)
            {
                log::warning(logcat, "Pending build to {} already underway... aborting...", path->upstream_rxid());
                return nullptr;
            }
        }

        log::debug(logcat, "Building path -> {} : {}", path->to_string(), path->hop_string());

        return path;
    }

    bool OutboundSession::is_ready() const
    {
        if (_pivot_txid.is_zero())
            return false;

        const size_t expect = (1 + (num_paths_desired / 2));

        return num_active_paths() >= expect;
    }

    bool OutboundSession::is_expired(std::chrono::milliseconds now) const
    {
        return now > _last_use && now - _last_use > path::DEFAULT_LIFETIME;
    }

    InboundSession::InboundSession(
        NetworkAddress remote,
        std::shared_ptr<path::Path> _path,
        handlers::SessionEndpoint& parent,
        HopID remote_pivot_txid,
        session_tag _t,
        bool use_tun,
        std::optional<shared_kx_data> kx_data)
        : BaseSession{
            parent._router,
            std::move(_path),
            parent,
            std::move(remote),
            std::move(remote_pivot_txid),
            std::move(_t),
            use_tun,
            false,
            std::move(kx_data)}
    {}

}  // namespace llarp::session
