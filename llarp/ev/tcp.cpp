#include "tcp.hpp"

#include <llarp/net/ip_packet.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    static auto logcat = oxen::log::Cat("ev-tcp");

    constexpr auto evconnlistener_deleter = [](::evconnlistener *e) {
        log::trace(logcat, "Invoking evconnlistener deleter!");
        if (e)
            evconnlistener_free(e);
    };

    /// Checks rv for being -1 and, if so, raises a system_error from errno.  Otherwise returns it.
    static int check_rv(int rv)
    {
#ifdef _WIN32
        if (rv == SOCKET_ERROR)
            throw std::system_error{WSAGetLastError(), std::system_category()};
#else
        if (rv == -1)
            throw std::system_error{errno, std::system_category()};
#endif
        return rv;
    }

    static void tcp_read_cb(struct bufferevent *bev, void *user_arg)
    {
        std::array<uint8_t, 2048> buf{};

        // Load data from input buffer to local buffer
        auto nwrite = bufferevent_read(bev, buf.data(), buf.size());

        log::trace(logcat, "TCP socket received {}B: {}", nwrite, buffer_printer{buf});

        auto *conn = reinterpret_cast<TCPConnection *>(user_arg);
        assert(conn);

        conn->stream->send(ustring{(buf.data()), nwrite});
    };

    static void tcp_event_cb(struct bufferevent *bev, short what, void *user_arg)
    {
        (void)bev;
        (void)user_arg;

        // this is where the InboundSession confirms it established a TCP connection to the backend app
        if (what & BEV_EVENT_CONNECTED)
        {
            log::info(logcat, "TCP connect operation finished!");
        }
        if (what & BEV_EVENT_ERROR)
        {
            log::critical(logcat, "TCP Connection encountered error from bufferevent");
        }
        if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
        {
            log::debug(logcat, "TCP Connection closing tunneled QUIC stream");

            auto *conn = reinterpret_cast<TCPConnection *>(user_arg);
            assert(conn);
            (void)conn;

            // conn->stream->close();
        }
    };

    static void tcp_listen_cb(
        struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *src, int socklen, void *user_arg)
    {
        oxen::quic::Address source{src, static_cast<socklen_t>(socklen)};
        log::debug(logcat, "TCP RECEIVED -- SRC:{}", source);

        auto *b = evconnlistener_get_base(listener);
        auto *bevent = bufferevent_socket_new(b, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

        auto *handle = reinterpret_cast<TCPHandle *>(user_arg);
        assert(handle);

        // make TCPConnection here!
        auto *conn = handle->_conn_maker(bevent, fd);

        bufferevent_setcb(bevent, tcp_read_cb, nullptr, tcp_event_cb, conn);
        bufferevent_enable(bevent, EV_READ | EV_WRITE);
    };

    static void tcp_err_cb(struct evconnlistener * /* e */, void *user_arg)
    {
        int ec = EVUTIL_SOCKET_ERROR();
        log::critical(logcat, "TCP LISTENER RECEIVED ERROR CODE {}:{}", ec, evutil_socket_error_to_string(ec));

        auto *handle = reinterpret_cast<TCPHandle *>(user_arg);
        assert(handle);
        (void)handle;

        // DISCUSS: close everything here?
    };

    TCPConnection::TCPConnection(struct bufferevent *_bev, evutil_socket_t _fd, std::shared_ptr<oxen::quic::Stream> _s)
        : bev{_bev}, fd{_fd}, stream{std::move(_s)}
    {}

    TCPConnection::~TCPConnection()
    {
        bufferevent_free(bev);
        log::debug(logcat, "TCPSocket shut down!");
    }

    void TCPConnection::close(uint64_t ec)
    {
        log::info(logcat, "TCP connection closing with application error code: {}", ec);
    }

    std::shared_ptr<TCPHandle> TCPHandle::make_server(
        const std::shared_ptr<EventLoop> &ev, tcpconn_hook cb, uint16_t port)
    {
        std::shared_ptr<TCPHandle> h{new TCPHandle(ev, std::move(cb), port)};
        return h;
    }

    std::shared_ptr<TCPHandle> TCPHandle::make_client(const std::shared_ptr<EventLoop> &ev, oxen::quic::Address connect)
    {
        std::shared_ptr<TCPHandle> h{new TCPHandle{ev, std::move(connect)}};
        return h;
    }

    TCPHandle::TCPHandle(const std::shared_ptr<EventLoop> &ev_loop, oxen::quic::Address connect)
        : _ev{ev_loop}, _connect{std::move(connect)}
    {
        assert(_ev);
    }

    TCPHandle::TCPHandle(const std::shared_ptr<EventLoop> &ev_loop, tcpconn_hook cb, uint16_t p)
        : _ev{ev_loop}, _conn_maker{std::move(cb)}
    {
        assert(_ev);

        if (!_conn_maker)
            throw std::logic_error{"TCPSocket construction requires a non-empty receive callback"};

        _init_server(p);
    }

    std::shared_ptr<TCPConnection> TCPHandle::connect(std::shared_ptr<oxen::quic::Stream> s, uint16_t port)
    {
        sockaddr_in _addr = _connect->in4();
        _addr.sin_port = htonl(port);

        struct bufferevent *_bev =
            bufferevent_socket_new(_ev->loop().get(), -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

        s->set_stream_data_cb([&](oxen::quic::Stream &, bstring_view data) {
            auto rv = bufferevent_write(_bev, data.data(), data.size());
            log::info(
                logcat,
                "Stream (id:{}) {} {}B to TCP buffer",
                s->stream_id(),
                rv < 0 ? "failed to write" : "successfully wrote",
                data.size());
        });

        auto tcp_conn = std::make_shared<TCPConnection>(_bev, -1, std::move(s));

        bufferevent_setcb(_bev, tcp_read_cb, nullptr, tcp_event_cb, tcp_conn.get());

        if (bufferevent_socket_connect(_bev, (struct sockaddr *)&_addr, sizeof(_addr)) < 0)
        {
            log::warning(logcat, "Failed to make bufferevent-based TCP connection!");
            return nullptr;
        }

        // only set after a call to bufferevent_socket_connect
        tcp_conn->fd = bufferevent_getfd(_bev);

        return tcp_conn;
    }

    void TCPHandle::_init_client() {}

    void TCPHandle::_init_server(uint16_t port)
    {
        sockaddr_in _tcp{};
        _tcp.sin_family = AF_INET;
        _tcp.sin_addr.s_addr = INADDR_ANY;
        _tcp.sin_port = htonl(port);

        _tcp_listener = _ev->template shared_ptr<struct evconnlistener>(
            evconnlistener_new_bind(
                _ev->loop().get(),
                tcp_listen_cb,
                this,
                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE,
                -1,
                reinterpret_cast<sockaddr *>(&_tcp),
                sizeof(sockaddr)),
            evconnlistener_deleter);

        if (not _tcp_listener)
        {
            throw std::runtime_error{
                "TCP listener construction failed: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};
        }

        _sock = evconnlistener_get_fd(_tcp_listener.get());
        check_rv(getsockname(_sock, *_bound, _bound->socklen_ptr()));
        evconnlistener_set_error_cb(_tcp_listener.get(), tcp_err_cb);
    }

    TCPHandle::~TCPHandle()
    {
        _tcp_listener.reset();
        log::debug(logcat, "TCPHandle shut down!");
    }
}  //  namespace llarp
