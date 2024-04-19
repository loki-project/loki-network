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

/** TODO:
    - set up session_map in EndpointBase
      - OutboundSession will create the path
    - separate Socket and Handle from QUIC-like "ownership" model
    - TCPHandle has a socket creation callback instead of a data callback
      - Fire socket creation cb on accepting connection
      - Socket creation cb could be given a created socket to set the callbacks on
    - QUIC stream held by TCPSocket needs to have a receive data callback that writes to the TCP connection
*/

namespace llarp
{
    class QUICTunnel;

    struct TCPConnection
    {
        TCPConnection() = delete;

        TCPConnection(struct bufferevent* _bev, evutil_socket_t _fd, std::shared_ptr<oxen::quic::Stream> _s);

        /// Non-copyable and non-moveable
        TCPConnection(const TCPConnection& s) = delete;
        TCPConnection& operator=(const TCPConnection& s) = delete;
        TCPConnection(TCPConnection&& s) = delete;
        TCPConnection& operator=(TCPConnection&& s) = delete;

        ~TCPConnection();

        struct bufferevent* bev;
        evutil_socket_t fd;

        std::shared_ptr<oxen::quic::Stream> stream;
    };

    using tcpsock_hook = std::function<TCPConnection*(struct bufferevent*, evutil_socket_t)>;

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
        oxen::quic::Address _bound{};

        socket_t _sock;

        explicit TCPHandle(const std::shared_ptr<EventLoop>& ev, tcpsock_hook cb);

      public:
        TCPHandle() = delete;

        tcpsock_hook _socket_maker;

        static std::shared_ptr<TCPHandle> make(const std::shared_ptr<EventLoop>& ev, tcpsock_hook cb);

        ~TCPHandle();

        uint16_t port() const
        {
            return _bound.port();
        }

        oxen::quic::Address bind() const
        {
            return _bound;
        }

      private:
        void _init_internals();
    };
}  //  namespace llarp
