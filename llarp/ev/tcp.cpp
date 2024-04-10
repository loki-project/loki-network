#include "tcp.hpp"

#include <llarp/address/ip_packet.hpp>
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

        auto *handle = reinterpret_cast<TCPHandle *>(user_arg);
        assert(handle);

        auto bfd = bufferevent_getfd(bev);

        if (auto maybe_str = handle->get_socket_stream(bfd))
        {
            log::trace(logcat, "TCP handle passing received data to corresponding stream!");
            maybe_str->send(ustring_view{buf.data(), nwrite});
        }
        else
        {
            log::error(logcat, "TCP handle could not find corresponding stream to fd:{}", bfd);
            handle->close_socket(bfd);
        }
    };

    static void tcp_event_cb(struct bufferevent *bev, short what, void *user_arg)
    {
        // This void pointer is the TCPSocket object. This opens the door for closing the TCP setup in case of any
        // failures
        (void)user_arg;

        if (what & BEV_EVENT_CONNECTED)
        {
            log::info(logcat, "TCP connect operation finished!");
        }
        if (what & BEV_EVENT_ERROR)
        {
            log::critical(logcat, "TCP listener encountered error from bufferevent");
        }
        if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
        {
            log::debug(logcat, "TCP listener freeing bufferevent...");
            bufferevent_free(bev);
        }
    };

    static void tcp_listen_cb(
        struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *src, int socklen, void *user_arg)
    {
        oxen::quic::Address source{src, static_cast<socklen_t>(socklen)};
        log::debug(logcat, "TCP RECEIVED -- SRC:{}", source);

        auto *b = evconnlistener_get_base(listener);
        auto *bevent = bufferevent_socket_new(b, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

        bufferevent_setcb(bevent, tcp_read_cb, nullptr, tcp_event_cb, user_arg);
        bufferevent_enable(bevent, EV_READ | EV_WRITE);

        auto *handle = reinterpret_cast<TCPHandle *>(user_arg);
        assert(handle);
    };

    static void tcp_err_cb(struct evconnlistener * /* e */, void *user_arg)
    {
        int ec = EVUTIL_SOCKET_ERROR();
        log::critical(logcat, "TCP LISTENER RECEIVED ERROR CODE {}:{}", ec, evutil_socket_error_to_string(ec));

        auto *handle = reinterpret_cast<TCPHandle *>(user_arg);
        assert(handle);

        // DISCUSS: close everything here?
    };

    TCPSocket::TCPSocket(struct bufferevent *_bev, const oxen::quic::Address &_src) : bev{_bev}, src{_src}
    {}

    TCPSocket::~TCPSocket()
    {
        bufferevent_free(bev);
        log::debug(logcat, "TCPSocket shut down!");
    }

    TCPHandle::TCPHandle(const std::shared_ptr<EventLoop> &ev_loop, const oxen::quic::Address &bind, rcv_data_hook cb)
        : _ev{ev_loop}, _receive_cb{std::move(cb)}
    {
        assert(_ev);

        if (!_receive_cb)
            throw std::logic_error{"TCPSocket construction requires a non-empty receive callback"};

        _init_internals(bind);
    }

    std::shared_ptr<oxen::quic::Stream> TCPHandle::get_socket_stream(evutil_socket_t fd)
    {
        if (auto itr = routing.find(fd); itr != routing.end())
        {
            if (auto str = itr->second->stream.lock())
                return str;
        }

        return nullptr;
    }

    void TCPHandle::close_socket(evutil_socket_t fd)
    {
        routing.erase(fd);
    }

    void TCPHandle::_init_internals(const oxen::quic::Address &bind)
    {
        sockaddr_in _tcp{};
        _tcp.sin_family = AF_INET;
        _tcp.sin_addr.s_addr = INADDR_ANY;
        _tcp.sin_port = htons(bind.port());

        _tcp_listener = _ev->shared_ptr<struct evconnlistener>(
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
        check_rv(getsockname(_sock, _bound, _bound.socklen_ptr()));
        evconnlistener_set_error_cb(_tcp_listener.get(), tcp_err_cb);
    }

    TCPHandle::~TCPHandle()
    {
        _tcp_listener.reset();
        log::debug(logcat, "TCPHandle shut down!");
    }
}  //  namespace llarp
