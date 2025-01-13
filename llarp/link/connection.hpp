#pragma once

#include <llarp/contact/relay_contact.hpp>
#include <llarp/contact/router_id.hpp>

#include <oxen/quic.hpp>

namespace llarp::link
{
    struct Connection
    {
        Connection(
            std::shared_ptr<oxen::quic::connection_interface> c,
            std::shared_ptr<oxen::quic::BTRequestStream> s,
            bool _is_relay = true,
            bool _is_active = false);

        std::shared_ptr<oxen::quic::connection_interface> conn;
        std::shared_ptr<oxen::quic::BTRequestStream> control_stream;

        std::atomic<bool> is_active{false};

        bool remote_is_relay{true};

        bool is_inbound() const { return conn->is_inbound(); }

        void close_quietly();
    };
}  // namespace llarp::link

/**
    TODO:
    - add a boolean in this connection object
    - do not continue to try to send things to the bootstrap until the connection is actually established!
 */
