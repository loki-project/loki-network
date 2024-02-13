#include "ip_packet.hpp"

#include <llarp/util/buffer.hpp>
#include <llarp/util/time.hpp>

#include <oxenc/endian.h>

#include <memory>
#include <utility>

namespace llarp
{
    IPPacket::IPPacket(size_t sz)
    {
        if (sz and sz < MIN_PACKET_SIZE)
            throw std::invalid_argument{"Buffer size is too small for an IP packet!"};
        _buf.resize(sz);
        std::fill(_buf.begin(), _buf.end(), 0);
    }

    IPPacket::IPPacket(bstring_view data) : IPPacket{reinterpret_cast<const unsigned char*>(data.data()), data.size()}
    {}

    IPPacket::IPPacket(ustring_view data) : IPPacket{data.data(), data.size()}
    {}

    IPPacket::IPPacket(std::vector<uint8_t> data) : IPPacket{data.data(), data.size()}
    {}

    IPPacket::IPPacket(const uint8_t* buf, size_t len)
    {
        if (len < MIN_PACKET_SIZE)
        {
            _buf.resize(0);
            return;
        }

        _buf.resize(len);
        std::copy_n(buf, len, _buf.data());
    }

    IPPacket IPPacket::from_udp(UDPPacket pkt)
    {
        auto& data = pkt.data;
        return IPPacket{reinterpret_cast<const unsigned char*>(data.data()), data.size()};
    }

    UDPPacket IPPacket::make_udp(ip src_addr, uint16_t src_port, ip dest_addr, uint16_t dest_port)
    {
        oxen::quic::Address src, dest;

        if (auto* maybe_src = std::get_if<ipv4>(&src_addr))
            src = oxen::quic::Address{*maybe_src, src_port};
        else if (auto* maybe_src = std::get_if<ipv6>(&src_addr))
            src = oxen::quic::Address{*maybe_src, src_port};
        else
            throw std::invalid_argument{"Could not parse IP src address for UDP Packet!"};

        if (auto* maybe_dest = std::get_if<ipv4>(&dest_addr))
            dest = oxen::quic::Address{*maybe_dest, dest_port};
        else if (auto* maybe_dest = std::get_if<ipv6>(&dest_addr))
            dest = oxen::quic::Address{*maybe_dest, dest_port};
        else
            throw std::invalid_argument{"Could not parse IP src address for UDP Packet!"};

        return make_udp(std::move(src), std::move(dest));
    }

    UDPPacket IPPacket::make_udp(oxen::quic::Address src, oxen::quic::Address dest)
    {
        return UDPPacket{oxen::quic::Path{std::move(src), std::move(dest)}, bview()};
    }

    bool IPPacket::load(ustring_view data)
    {
        return load(data.data(), data.size());
    }

    bool IPPacket::load(std::string_view data)
    {
        return load(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    bool IPPacket::load(std::vector<uint8_t> data)
    {
        return load(data.data(), data.size());
    }

    bool IPPacket::load(const uint8_t* buf, size_t len)
    {
        if (len < MIN_PACKET_SIZE)
            return false;

        _buf.clear();
        _buf.resize(len);
        std::copy_n(buf, len, _buf.data());
        return true;
    }

    bool IPPacket::take(std::vector<uint8_t> data)
    {
        auto len = data.size();
        if (len < MIN_PACKET_SIZE)
            return false;

        _buf.clear();
        _buf.resize(len);
        std::memmove(_buf.data(), data.data(), len);
        return true;
    }

    std::vector<uint8_t> IPPacket::steal() &&
    {
        std::vector<uint8_t> b;
        b.resize(size());
        _buf.swap(b);
        return b;
    }

    std::vector<uint8_t> IPPacket::give()
    {
        std::vector<uint8_t> b;
        b.resize(size());
        std::memcpy(b.data(), data(), size());
        return b;
    }

    std::string IPPacket::to_string()
    {
        return {reinterpret_cast<const char*>(data()), size()};
    }

}  // namespace llarp
