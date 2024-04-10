#include "udp.hpp"

namespace llarp
{
    static auto logcat = log::Cat("ev-udp");

    inline constexpr size_t MAX_BATCH =
#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
        24;
#else
        1;
#endif

    UDPHandle::UDPHandle(const std::shared_ptr<EventLoop>& ev, const oxen::quic::Address& bind, udp_pkt_hook cb)
        : _loop{ev}
    {
        socket = std::make_unique<UDPSocket>(ev->loop().get(), bind, std::move(cb));
        _local = socket->address();
    }

    io_result UDPHandle::_send_impl(
        const oxen::quic::Path& path, std::byte* buf, size_t* bufsize, uint8_t ecn, size_t& n_pkts)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (!socket)
        {
            log::warning(logcat, "Cannot send packets on closed socket ({})", path);
            return io_result{EBADF};
        }

        assert(n_pkts >= 1 && n_pkts <= MAX_BATCH);

        log::trace(logcat, "Sending {} UDP packet(s) {}...", n_pkts, path);

        auto [ret, sent] = socket->send(path, buf, bufsize, ecn, n_pkts);

        if (ret.failure() && !ret.blocked())
        {
            log::error(logcat, "Error sending packets {}: {}", path, ret.str_error());
            n_pkts = 0;  // Drop any packets, as we had a serious error
            return ret;
        }

        if (sent < n_pkts)
        {
            if (sent == 0)  // Didn't send *any* packets, i.e. we got entirely blocked
                log::debug(logcat, "UDP sent none of {}", n_pkts);

            else
            {
                // We sent some but not all, so shift the unsent packets back to the beginning of buf/bufsize
                log::debug(logcat, "UDP undersent {}/{}", sent, n_pkts);
                size_t offset = std::accumulate(bufsize, bufsize + sent, size_t{0});
                size_t len = std::accumulate(bufsize + sent, bufsize + n_pkts, size_t{0});
                std::memmove(buf, buf + offset, len);
                std::copy(bufsize + sent, bufsize + n_pkts, bufsize);
                n_pkts -= sent;
            }

            // We always return EAGAIN (so that .blocked() is true) if we failed to send all, even
            // if that isn't strictly what we got back as the return value (sendmmsg gives back a
            // non-error on *partial* success).
            return io_result{EAGAIN};
        }

        n_pkts = 0;

        return ret;
    }

    void UDPHandle::_send_or_queue(
        const oxen::quic::Path& path, std::vector<std::byte> buf, uint8_t ecn, std::function<void(io_result)> callback)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (!socket)
        {
            log::warning(logcat, "Cannot sent to dead socket for path {}", path);
            if (callback)
                callback(io_result{EBADF});
            return;
        }

        size_t n_pkts = 1;
        size_t bufsize = buf.size();
        auto res = _send_impl(path, buf.data(), &bufsize, ecn, n_pkts);

        if (res.blocked())
        {
            socket->when_writeable([this, path, buf = std::move(buf), ecn, cb = std::move(callback)]() mutable {
                _send_or_queue(path, std::move(buf), ecn, std::move(cb));
            });
        }
        else if (callback)
            callback({});
    }
}  //  namespace llarp
