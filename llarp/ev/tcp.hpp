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
    class TCPHandle;

    struct TCPSocket
    {
        TCPSocket() = delete;

        TCPSocket(struct bufferevent* _bev, const oxen::quic::Address& _src);

        /// Non-copyable and non-moveable
        TCPSocket(const TCPSocket& s) = delete;
        TCPSocket& operator=(const TCPSocket& s) = delete;
        TCPSocket(TCPSocket&& s) = delete;
        TCPSocket& operator=(TCPSocket&& s) = delete;

        ~TCPSocket();

        struct bufferevent* bev;
        oxen::quic::Address src;

        std::weak_ptr<oxen::quic::Stream> stream;
    };

    class TCPHandle
    {
      public:
        using socket_t =
#ifndef _WIN32
            int
#else
            SOCKET
#endif
            ;
        TCPHandle() = delete;

        explicit TCPHandle(const std::shared_ptr<EventLoop>& ev, const oxen::quic::Address& bind, rcv_data_hook cb);

        ~TCPHandle();

      private:
        std::shared_ptr<EventLoop> _ev;
        std::shared_ptr<::evconnlistener> _tcp_listener;

        socket_t _sock;
        oxen::quic::Address _bound;
        rcv_data_hook _receive_cb;

        std::unordered_map<evutil_socket_t, std::shared_ptr<TCPSocket>> routing;

        void _init_internals(const oxen::quic::Address& bind);

      public:
        // void map_buffer_socket(evutil_socket_t fd)

        std::shared_ptr<oxen::quic::Stream> get_socket_stream(evutil_socket_t fd);

        void close_socket(evutil_socket_t fd);

        oxen::quic::Address bind()
        {
            return _bound;
        }
    };
}  //  namespace llarp
