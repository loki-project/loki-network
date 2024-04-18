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

    struct TCPSocket
    {
        TCPSocket() = delete;

        TCPSocket(struct bufferevent* _bev, evutil_socket_t _fd, const oxen::quic::Address& _src);

        /// Non-copyable and non-moveable
        TCPSocket(const TCPSocket& s) = delete;
        TCPSocket& operator=(const TCPSocket& s) = delete;
        TCPSocket(TCPSocket&& s) = delete;
        TCPSocket& operator=(TCPSocket&& s) = delete;

        ~TCPSocket();

        struct bufferevent* bev;
        evutil_socket_t fd;
        oxen::quic::Address src;

        std::shared_ptr<oxen::quic::Stream> stream;
    };

    using tcpsock_hook = std::function<std::shared_ptr<TCPSocket>()>;

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
        oxen::quic::Address _bound;

        socket_t _sock;
        tcpsock_hook _socket_maker;

        std::unordered_map<evutil_socket_t, std::shared_ptr<TCPSocket>> routing;

      public:
        TCPHandle() = delete;

        explicit TCPHandle(const std::shared_ptr<EventLoop>& ev, const oxen::quic::Address& bind, tcpsock_hook cb);

        ~TCPHandle();

        oxen::quic::Address bind() const
        {
            return _bound;
        }

      private:
        void _init_internals(const oxen::quic::Address& bind);
    };
}  //  namespace llarp
