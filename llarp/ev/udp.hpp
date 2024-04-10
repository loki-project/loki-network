#pragma once

#include "loop.hpp"

#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>

namespace llarp
{
    class EventLoop;

    class UDPHandle
    {
      public:
        UDPHandle() = delete;
        explicit UDPHandle(const std::shared_ptr<EventLoop>& ev, const oxen::quic::Address& bind, udp_pkt_hook cb);
        ~UDPHandle();

      private:
        std::shared_ptr<EventLoop> _loop;
        std::unique_ptr<UDPSocket> socket;
        oxen::quic::Address _local;

        io_result _send_impl(
            const oxen::quic::Path& path, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts);

        void _send_or_queue(
            const oxen::quic::Path& path,
            std::vector<std::byte> buf,
            uint8_t ecn,
            std::function<void(io_result)> callback = nullptr);

      public:
        io_result send(const oxen::quic::Address& dest, bstring data);

        io_result send(const oxen::quic::Address& dest, std::vector<uint8_t> data);

        oxen::quic::Address bind()
        {
            return _local;
        }

        void close();
    };

}  //  namespace llarp
