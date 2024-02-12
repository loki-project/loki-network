#pragma once

#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>

#include <oxen/quic.hpp>

namespace llarp
{
    static auto logcat = log::Cat("UDP");

    using IPPacket = oxen::quic::Packet;

    using udp_recv_hook = oxen::quic::UDPSocket::receive_callback_t;

    using UDPSocket = oxen::quic::UDPSocket;

    using io_result = oxen::quic::io_result;

    struct UDPHandle
    {
      private:
        std::unique_ptr<UDPSocket> socket;
        oxen::quic::Address _local;

        io_result _send_impl(const oxen::quic::Path& path, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts);

        void _send_or_queue(const oxen::quic::Path& path, std::vector<std::byte> buf, uint8_t ecn, std::function<void(io_result)> callback = nullptr);

      public:
        io_result send(const oxen::quic::Address& dest, bstring data);

    };

}   //  namespace llarp
