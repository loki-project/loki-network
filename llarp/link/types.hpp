#pragma once

#include <oxen/quic.hpp>

namespace llarp
{
    using bt_control_stream = std::shared_ptr<oxen::quic::BTRequestStream>;
    using bt_control_response_hook = std::function<void(oxen::quic::message)>;
    using bt_control_send_hook = std::function<void(const bt_control_stream&)>;

    using conn_open_hook = oxen::quic::connection_established_callback;
    using conn_closed_hook = oxen::quic::connection_closed_callback;
    using stream_open_hook = oxen::quic::stream_open_callback;
    using stream_closed_hook = oxen::quic::stream_close_callback;

    using keep_alive = oxen::quic::opt::keep_alive;
    using inbound_alpns = oxen::quic::opt::inbound_alpns;
    using outbound_alpns = oxen::quic::opt::outbound_alpns;

    using static_secret = oxen::quic::opt::static_secret;
}  // namespace llarp
