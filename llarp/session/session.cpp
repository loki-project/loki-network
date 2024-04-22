#include "session.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/handlers/session.hpp>
#include <llarp/link/tunnel.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path.hpp>
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
        service::SessionTag _t,
        bool use_tun,
        bool is_outbound)
        : _r{r},
          _parent{parent},
          _tag{std::move(_t)},
          _remote{std::move(remote)},
          _use_tun{use_tun},
          _is_outbound{is_outbound}
    {
        set_new_current_path(std::move(_p));
    }

    bool BaseSession::send_path_control_message(
        std::string method, std::string body, std::function<void(std::string)> func)
    {
        return _current_path->send_path_control_message(std::move(method), std::move(body), std::move(func));
    }

    bool BaseSession::send_path_data_message(std::string data)
    {
        return _current_path->send_path_data_message(std::move(data));
    }

    void BaseSession::recv_path_data_message(bstring body)
    {
        _current_path->recv_path_data_message(std::move(body));
    }

    void BaseSession::set_new_current_path(std::shared_ptr<path::Path> _new_path)
    {
        if (_current_path)
            _current_path->unlink_session();

        _current_path = std::move(_new_path);

        _current_hop_id = _current_path->intro.pivot_hop_id;

        if (_use_tun)
            _current_path->link_session(
                [this](bstring data) { _r.tun_endpoint()->handle_outbound_packet(std::move(data)); });
        else
            _current_path->link_session([this](bstring data) {
                _ep->manually_receive_packet(UDPPacket{oxen::quic::Path{}, std::move(data)});
            });

        assert(_current_path->is_linked());
    }

    void BaseSession::_init_ep()
    {
        _ep = _r.quic_tunnel()->net()->endpoint(
            oxen::quic::Address{}, oxen::quic::opt::manual_routing{[this](const oxen::quic::Path&, bstring_view data) {
                _current_path->send_path_data_message(
                    std::string{reinterpret_cast<const char*>(data.data()), data.size()});
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
            });

        _handles.emplace(_handle->port(), std::move(_handle));
    }

    void BaseSession::tcp_backend_listen(uint16_t port)
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

        _handles.emplace(_handle->port(), std::move(_handle));

        // connect OutboundSession tunneled ep to InboundSession's tunneled ep
        _ci = _ep->connect(KeyedAddress{TUNNEL_PUBKEY}, _r.quic_tunnel()->creds());
    }

    OutboundSession::OutboundSession(
        NetworkAddress remote,
        handlers::SessionEndpoint& parent,
        std::shared_ptr<path::Path> path,
        service::SessionTag _t,
        bool is_exit)
        : PathHandler{parent._router, path::DEFAULT_PATHS_HELD},
          BaseSession{_router, std::move(path), parent, std::move(remote), std::move(_t), _router.using_tun_if(), true},
          _last_use{_router.now()},
          _is_exit_service{is_exit},
          _is_snode_service{not _remote.is_client()}
    {
        // These can both be false but CANNOT both be true
        if (_is_exit_service and _is_snode_service)
            throw std::runtime_error{"Cannot create OutboundSession for a remote exit and remote service!"};

        add_path(_current_path);

        if (_is_snode_service)
            _session_key = _router.identity();
        else
            crypto::identity_keygen(_session_key);
    }

    OutboundSession::~OutboundSession() = default;

    void OutboundSession::path_died(std::shared_ptr<path::Path> p)
    {
        p->rebuild();
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

    void OutboundSession::blacklist_snode(const RouterID& snode)
    {
        (void)snode;
    }

    bool OutboundSession::is_path_dead(std::shared_ptr<path::Path>, std::chrono::milliseconds dlt)
    {
        return dlt >= path::ALIVE_TIMEOUT;
    }

    void OutboundSession::path_build_succeeded(std::shared_ptr<path::Path> p)
    {
        path::PathHandler::path_build_succeeded(p);

        // TODO: why the fuck did we used to do this here...?
        // if (p->obtain_exit(_auth->session_key(), _is_snode_service ? 1 : 0, p->upstream_txid().to_string()))
        //     log::info(logcat, "Asking {} for exit", _remote);
        // else
        //     log::warning(logcat, "Failed to send exit request");
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
        _running = false;

        Lock_t l{paths_mutex};

        for (auto itr = _paths.begin(); itr != _paths.end();)
        {
            auto& p = itr->second;

            dissociate_hop_ids(p);

            if (send_close)
            {
                log::info(logcat, "Sending close_exit on path {}", p->to_string());
                send_path_close(p);
            }

            itr = _paths.erase(itr);
        }

        return true;
    }

    void OutboundSession::build_more(size_t n)
    {
        size_t count{0};
        log::debug(
            logcat,
            "OutboundSession building {} paths (needed: {}) to remote:{}",
            n,
            path::DEFAULT_PATHS_HELD,
            _remote);

        for (size_t i = 0; i < n; ++i)
        {
            count += build_path_aligned_to_remote(_remote);
        }

        if (count == n)
            log::debug(logcat, "OutboundSession successfully initiated {} path-builds", n);
        else
            log::warning(logcat, "OutboundSession only initiated {} path-builds (needed: {})", count, n);
    }

    std::shared_ptr<path::Path> OutboundSession::build1(std::vector<RemoteRC>& hops)
    {
        auto path = std::make_shared<path::Path>(_router, hops, get_weak(), true, _remote.is_client());

        log::info(logcat, "Building path -> {} : {}", path->to_string(), path->HopsString());

        return path;
    }

    void OutboundSession::send_path_close(std::shared_ptr<path::Path> p)
    {
        if (p->close_exit(_session_key, p->upstream_txid().to_string()))
            log::info(logcat, "Sent path close on path {}", p->to_string());
        else
            log::warning(logcat, "Failed to send path close on path {}", p->to_string());
    }

    bool OutboundSession::is_ready() const
    {
        if (_current_hop_id.is_zero())
            return false;

        const size_t expect = (1 + (num_paths_desired / 2));

        return num_paths() >= expect;
    }

    bool OutboundSession::is_expired(std::chrono::milliseconds now) const
    {
        return now > _last_use && now - _last_use > path::DEFAULT_LIFETIME;
    }

    InboundSession::InboundSession(
        NetworkAddress remote,
        std::shared_ptr<path::Path> _path,
        handlers::SessionEndpoint& parent,
        service::SessionTag _t,
        bool use_tun)
        : BaseSession{parent._router, std::move(_path), parent, std::move(remote), std::move(_t), use_tun, false},
          _is_exit_node{_parent.is_exit_node()}
    {
        if (not _current_path->is_client_path() and _remote.is_client())
            throw std::runtime_error{
                "NetworkAddress and Path do not agree on InboundSession remote's identity (client vs server)!"};
    }

    void InboundSession::set_new_tag(const service::SessionTag& tag)
    {
        _tag = tag;
    }
}  // namespace llarp::session
