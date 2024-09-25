#pragma once

#include "loop.hpp"

#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>

extern "C"
{
#include <arpa/inet.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
}

namespace llarp
{
    class QUICTunnel;

    struct TCPConnection
    {
        TCPConnection(struct bufferevent* _bev, evutil_socket_t _fd, std::shared_ptr<oxen::quic::Stream> _s);

        TCPConnection() = delete;

        /// Non-copyable and non-moveable
        TCPConnection(const TCPConnection& s) = delete;
        TCPConnection& operator=(const TCPConnection& s) = delete;
        TCPConnection(TCPConnection&& s) = delete;
        TCPConnection& operator=(TCPConnection&& s) = delete;

        ~TCPConnection();

        struct bufferevent* bev;
        evutil_socket_t fd;

        std::shared_ptr<oxen::quic::Stream> stream;

        void close(uint64_t ec = 0);
    };

    using tcpconn_hook = std::function<TCPConnection*(struct bufferevent*, evutil_socket_t)>;

    class TCPHandle
    {
        using socket_t =
#ifndef _WIN32
            int
#else
            SOCKET
#endif
            ;

        std::shared_ptr<EventLoop> _ev;
        std::shared_ptr<::evconnlistener> _tcp_listener;

        // The OutboundSession will set up an evconnlistener and set the listening socket address inside ::_bound
        std::optional<oxen::quic::Address> _bound = std::nullopt;

        // The InboundSession will set this address to the lokinet-primary-ip to connect to
        std::optional<oxen::quic::Address> _connect = std::nullopt;

        socket_t _sock;

        explicit TCPHandle(const std::shared_ptr<EventLoop>& ev, tcpconn_hook cb, uint16_t p);

        explicit TCPHandle(const std::shared_ptr<EventLoop>& ev, oxen::quic::Address connect);

      public:
        TCPHandle() = delete;

        tcpconn_hook _conn_maker;

        // The OutboundSession object will hold a server listening on some localhost:port, returning that port to the
        // application for it to make a TCP connection
        static std::shared_ptr<TCPHandle> make_server(
            const std::shared_ptr<EventLoop>& ev, tcpconn_hook cb, uint16_t port = 0);

        // The InboundSession object will hold a client that connects to some application configured
        // lokinet-primary-ip:port every time the OutboundSession opens a new stream over the tunneled connection
        static std::shared_ptr<TCPHandle> make_client(
            const std::shared_ptr<EventLoop>& ev, oxen::quic::Address connect);

        ~TCPHandle();

        uint16_t port() const { return _bound.has_value() ? _bound->port() : 0; }

        std::optional<oxen::quic::Address> bind() const { return _bound; }

        std::shared_ptr<TCPConnection> connect(std::shared_ptr<oxen::quic::Stream> s, uint16_t port = 0);

      private:
        void _init_client();

        void _init_server(uint16_t port);
    };
}  //  namespace llarp
