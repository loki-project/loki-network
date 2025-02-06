#include "session.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/handlers/session.hpp>
#include <llarp/link/tunnel.hpp>
#include <llarp/messages/path.hpp>
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
          _is_snode_session{_is_outbound ? !_remote.is_client() : r.is_service_node()}
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

    bool BaseSession::send_path_control_message(
        std::string method, std::string body, std::function<void(oxen::quic::message)> func)
    {
        return _current_path->send_path_control_message(std::move(method), std::move(body), std::move(func));
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

        log::critical(logcat, "Populating intro map for {} intros!", _remote_intros.size());

        for (auto& intro : _remote_intros)
        {
            if (intro.pivot_rid == _current_path->pivot_rid())
                intro_path_mapping.emplace(intro, path::PathPtrSet{_current_path});
            else
                intro_path_mapping.emplace(intro, path::PathPtrSet{});
        }
    }

    OutboundSession::~OutboundSession() = default;

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

    void OutboundSession::blacklist_snode(const RouterID& snode) { (void)snode; }

    void OutboundSession::path_build_succeeded(std::shared_ptr<path::Path> p)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        for (auto& [intro, pathset] : intro_path_mapping)
        {
            if (intro.pivot_rid == p->pivot_rid())
            {
                pathset.emplace(p);
                log::debug(logcat, "Client intro {} has {} paths to remote pivot", intro, pathset.size());
                break;
            }
        }

        path::PathHandler::path_build_succeeded(p);
    }

    void OutboundSession::path_build_failed(std::shared_ptr<path::Path> p, bool timeout)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);
        Lock_t l(paths_mutex);

        for (auto& [intro, pathset] : intro_path_mapping)
        {
            if (intro.pivot_rid == p->pivot_rid())
            {
                pathset.erase(p);
                log::debug(logcat, "Client intro {} has {} paths to remote pivot", intro, pathset.size());
                break;
            }
        }

        path::PathHandler::path_build_failed(p, timeout);
    }

    void OutboundSession::reset_path_state()
    {
        // TODO: should we be closing exits on internal state reset?
        auto sendExitClose = [&](const std::shared_ptr<path::Path> p) {
            // const static auto roles = llarp::path::ePathRoleExit | llarp::path::ePathRoleSVC;
            (void)p;

            // if (p->SupportsAnyRoles(roles))
            // {
            //   log::info(logcat, "{} closing exit path", p->name());
            //   if (p->close_exit(_session_key, p->TXID().bt_encode()))
            //     p->ClearRoles(roles);
            //   else
            //     llarp::LogWarn(p->name(), " failed to send exit close message");
            // }
        };

        for_each_path(sendExitClose);
        path::PathHandler::reset_path_state();
    }

    bool OutboundSession::stop(bool send_close)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _running = false;

        if (send_close)
        {
            std::promise<void> prom;
            auto f = prom.get_future();

            _router.loop()->call([&]() mutable {
                Lock_t l{paths_mutex};

                for (auto& [_, p] : _paths)
                {
                    if (p and p->is_ready())
                    {
                        log::debug(logcat, "Sending close message on path {}", p->to_string());
                        // send_path_close(p);
                    }
                }

                prom.set_value();
            });

            f.get();
            log::info(logcat, "All paths dispatched path close message!");
        }

        intro_path_mapping.clear();

        // base class dtor clears path map
        return path::PathHandler::stop(send_close);
    }

    // void OutboundSession::tick(std::chrono::milliseconds /* now */)
    // {
    //     log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

    //     Lock_t l{paths_mutex};
    //     size_t needed = num_paths_desired;

    //     for (auto& [intro, count] : intro_path_count)
    //     {
    //         log::trace(
    //             logcat,
    //             "OutboundSession holding {}/{} paths needed to pivot:{}",
    //             count,
    //             PATHS_PER_INTRO,
    //             intro.pivot_rid);

    //         while (count < PATHS_PER_INTRO)
    //             count += build_path_aligned_to_remote(intro.pivot_rid);

    //         if (needed < count)
    //             break;

    //         needed -= count;
    //     }
    // }

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

            log::debug(
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

        log::info(logcat, "Building path -> {} : {}", path->to_string(), path->hop_string());

        return path;
    }

    void OutboundSession::send_path_close(std::shared_ptr<path::Path> p)
    {
        (void)p;
        // if (p->close_exit(_session_key, p->upstream_txid().to_string()))
        //     log::info(logcat, "Sent path close on path {}", p->to_string());
        // else
        //     log::warning(logcat, "Failed to send path close on path {}", p->to_string());
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
