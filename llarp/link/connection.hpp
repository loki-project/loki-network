#pragma once

#include "types.hpp"

#include <llarp/contact/relay_contact.hpp>
#include <llarp/contact/router_id.hpp>

namespace llarp::link
{
    struct Connection
    {
        Connection(
            std::shared_ptr<oxen::quic::connection_interface> c,
            bt_control_stream s,
            bool _is_relay = true,
            bool _is_active = false);

        std::shared_ptr<oxen::quic::connection_interface> conn;
        bt_control_stream control_stream;

        std::atomic<bool> is_active{false};

        bool remote_is_relay{true};

        bool is_inbound() const { return conn->is_inbound(); }

        void close_quietly();
    };
}  // namespace llarp::link
