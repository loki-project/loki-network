#pragma once

#include <oxen/quic.hpp>

namespace llarp
{
    using UDPPacket = oxen::quic::Packet;

    using udp_pkt_hook = oxen::quic::UDPSocket::receive_callback_t;

    using UDPSocket = oxen::quic::UDPSocket;

    using io_result = oxen::quic::io_result;

    using event_ptr = oxen::quic::event_ptr;

    // shared_ptr containing the actual libev loop
    using loop_ptr = std::shared_ptr<::event_base>;

    // Libevent callbacks
    using event_hook = std::function<void()>;

}  //  namespace llarp
