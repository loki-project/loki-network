#include "ip_packet.hpp"

#include "utils.hpp"

#include <llarp/util/buffer.hpp>
#include <llarp/util/logging/buffer.hpp>
#include <llarp/util/time.hpp>

#include <oxenc/endian.h>

#include <cstddef>
#include <utility>

namespace llarp
{
    static auto logcat = log::Cat("ip_packet");

    IPPacket::IPPacket(size_t sz)
    {
        if (sz and sz < MIN_PACKET_SIZE)
            throw std::invalid_argument{"Buffer size is too small for an IP packet!"};
        _buf.resize(sz);
        std::fill(_buf.begin(), _buf.end(), 0);
    }

    IPPacket::IPPacket(bstring_view data) : IPPacket{reinterpret_cast<const unsigned char*>(data.data()), data.size()}
    {}

    IPPacket::IPPacket(ustring_view data) : IPPacket{data.data(), data.size()} {}

    IPPacket::IPPacket(std::vector<uint8_t>&& data) : IPPacket{data.data(), data.size()} {}

    IPPacket::IPPacket(const uint8_t* buf, size_t len)
    {
        if (len >= MIN_PACKET_SIZE)
        {
            _buf.resize(len);
            std::memcpy(_buf.data(), buf, len);
        }

        _init_internals();
    }

    IPPacket IPPacket::from_netpkt(NetworkPacket pkt)
    {
        auto data = pkt.data();
        return IPPacket{reinterpret_cast<const unsigned char*>(data.data()), data.size()};
    }

    std::optional<IPPacket> IPPacket::from_buffer(const uint8_t* buf, size_t len)
    {
        std::optional<IPPacket> ret = std::nullopt;

        if (IPPacket b; b.load(buf, len))
            ret.emplace(std::move(b));

        return ret;
    }

    void IPPacket::_init_internals()
    {
        _header = reinterpret_cast<ip_header*>(data());
        _v6_header = reinterpret_cast<ipv6_header*>(data());

        if (_buf.empty())
            return;

        // log::trace(logcat, "ippkt header: {}", buffer_printer{_buf});
        // log::trace(logcat, "ippkt protocol: {}", _header->protocol);
        // log::trace(logcat, "ippkt version: {}", _header->version);

        _is_v4 = _header->version == oxenc::host_to_big(uint8_t{4});
        _is_udp = _header->protocol == uint8_t{17};

        uint16_t src_port =
            (_is_udp) ? *reinterpret_cast<uint16_t*>(data() + (static_cast<ptrdiff_t>(_header->header_len) * 4)) : 0;
        uint16_t dest_port = (_is_udp)
            ? *reinterpret_cast<uint16_t*>(data() + (static_cast<ptrdiff_t>(_header->header_len) * 4) + 2)
            : 0;

        if (_is_v4)
        {
            auto srcv4 = ipv4{oxenc::big_to_host(_header->src)};
            auto dstv4 = ipv4{oxenc::big_to_host(_header->dest)};

            log::trace(logcat, "srcv4={}:{}, dstv4={}:{}", srcv4, src_port, dstv4, dest_port);

            _src_addr = oxen::quic::Address{srcv4, src_port};
            _dst_addr = oxen::quic::Address{dstv4, dest_port};
        }
        else
        {
            auto srcv6 = ipv6{&_v6_header->srcaddr};
            auto dstv6 = ipv6{&_v6_header->dstaddr};

            log::trace(logcat, "srcv6={}:{}, dstv6={}:{}", srcv6, src_port, dstv6, dest_port);

            _src_addr = oxen::quic::Address{srcv6, src_port};
            _dst_addr = oxen::quic::Address{dstv6, dest_port};
        }
    }

    std::optional<std::pair<const char*, size_t>> IPPacket::l4_data() const
    {
        size_t hdr_sz = 0;

        if (_header->protocol == 0x11)
        {
            hdr_sz = 8;
        }
        else
            return std::nullopt;

        // check for invalid size
        if (size() < (static_cast<size_t>(_header->header_len) * 4) + hdr_sz)
            return std::nullopt;

        const uint8_t* ptr = data() + ((static_cast<size_t>(_header->header_len) * 4) + hdr_sz);

        return std::make_pair(reinterpret_cast<const char*>(ptr), std::distance(ptr, data() + size()));
    }

    void IPPacket::update_ipv4_address(ipv4 src, ipv4 dst)
    {
        log::debug(logcat, "Setting new source ({}) and destination ({}) IPs", src, dst);

        std::basic_string_view<uint16_t> head_u16s{reinterpret_cast<const uint16_t*>(_header), sizeof(ip_header)};
        // set new IP addresses
        _header->src = src.addr;
        _header->dest = dst.addr;

        switch (_header->protocol)
        {
            case 6:    // TCP
            case 17:   // UDP
            case 136:  // UDP-Lite - same checksum place, same 0->0xFFff condition
            case 33:   // DCCP
                _header->checksum = tcpudp_checksum_ipv4(
                    _header->src, _header->dest, _header->header_len, _header->protocol, _header->checksum);
                break;
            default:
                // do nothing
                break;
        }

        // IPv4 checksum
        auto v4chk = (uint16_t*)&(_header->checksum);
        *v4chk = checksum_ipv4(_header, _header->header_len);

        _init_internals();
    }

    void IPPacket::update_ipv6_address(ipv6 src, ipv6 dst, std::optional<uint32_t> flowlabel)
    {
        const size_t ihs = 4 + 4 + 16 + 16;
        const auto sz = size();
        // XXX should've been checked at upper level?
        if (sz <= ihs)
            return;

        auto hdr = v6_header();
        if (flowlabel.has_value())
        {
            // set flow label if desired
            hdr->set_flowlabel(*flowlabel);
        }

        // IPv6 address
        hdr->srcaddr = src.to_in6();
        hdr->dstaddr = dst.to_in6();

        // TODO IPv6 header options
        auto* pld = data() + ihs;
        auto psz = sz - ihs;

        size_t fragoff = 0;
        auto nextproto = hdr->protocol;
        for (;;)
        {
            switch (nextproto)
            {
                case 0:   // Hop-by-Hop Options
                case 43:  // Routing Header
                case 60:  // Destination Options
                {
                    nextproto = pld[0];
                    auto addlen = (size_t(pld[1]) + 1) * 8;
                    if (psz < addlen)
                        return;
                    pld += addlen;
                    psz -= addlen;
                    break;
                }

                case 44:  // Fragment Header
                    /*
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Identification                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     */
                    nextproto = pld[0];
                    fragoff = (uint16_t(pld[2]) << 8) | (uint16_t(pld[3]) & 0xFC);
                    if (psz < 8)
                        return;
                    pld += 8;
                    psz -= 8;

                    // jump straight to payload processing
                    if (fragoff != 0)
                        goto endprotohdrs;
                    break;

                default:
                    goto endprotohdrs;
            }
        }
    endprotohdrs:

        uint16_t chksumoff{0};
        uint16_t chksum{0};

        switch (nextproto)
        {
            case 6:  // TCP
                chksumoff = 16;
                [[fallthrough]];
            case 33:  // DCCP
                chksum = tcp_checksum_ipv6(&hdr->srcaddr, &hdr->dstaddr, hdr->payload_len, 0);

                // ones-complement addition fo 0xFFff is 0; this is verboten
                if (chksum == 0xFFff)
                    chksum = 0x0000;

                chksumoff = chksumoff == 16 ? 16 : 6;
                _is_udp = false;
                break;
            case 17:   // UDP
            case 136:  // UDP-Lite - same checksum place, same 0->0xFFff condition
                chksum = udp_checksum_ipv6(&hdr->srcaddr, &hdr->dstaddr, hdr->payload_len, 0);
                _is_udp = true;
                break;
            default:
                // do nothing
                break;
        }

        auto check = _is_udp ? (uint16_t*)(pld + 6) : (uint16_t*)(pld + chksumoff - fragoff);

        *check = chksum;

        _init_internals();
    }

    std::optional<IPPacket> IPPacket::make_icmp_unreachable() const
    {
        if (is_ipv4())
        {
            auto ip_hdr_sz = _header->header_len * 4;
            auto pkt_size = (ICMP_HEADER_SIZE + ip_hdr_sz) * 2;

            IPPacket pkt{static_cast<size_t>(pkt_size)};

            _header->version = 4;
            _header->header_len = 0x05;
            _header->service_type = 0;
            _header->checksum = 0;
            _header->total_len = ntohs(pkt_size);
            _header->src = _header->dest;
            _header->dest = _header->src;
            _header->protocol = 1;  // ICMP
            _header->ttl = _header->ttl;
            _header->frag_off = htons(0b0100000000000000);

            uint16_t* checksum;
            uint8_t* itr = pkt.data() + ip_hdr_sz;
            uint8_t* icmp_begin = itr;  // type 'destination unreachable'
            *itr++ = 3;

            // code 'Destination host unknown error'
            *itr++ = 7;

            // checksum + unused
            oxenc::write_host_as_big<uint32_t>(0, itr);
            checksum = (uint16_t*)itr;
            itr += 4;

            // next hop mtu is ignored but let's put something here anyways just in case tm
            oxenc::write_host_as_big<uint16_t>(1500, itr);
            itr += 2;

            // copy ip header and first 8 bytes of datagram for icmp rject
            std::memcpy(itr, _buf.data(), ip_hdr_sz + ICMP_HEADER_SIZE);
            itr += ip_hdr_sz + ICMP_HEADER_SIZE;

            // calculate checksum of ip header
            _header->checksum = checksum_ipv4(_header, _header->header_len);
            const auto icmp_size = std::distance(icmp_begin, itr);

            // calculate icmp checksum
            *checksum = checksum_ipv4(icmp_begin, icmp_size);
            return pkt;
        }
        return std::nullopt;
    }

    NetworkPacket IPPacket::make_netpkt() &&
    {
        bstring data{};
        data.reserve(_buf.size());
        std::memcpy(data.data(), _buf.data(), _buf.size());
        return NetworkPacket{oxen::quic::Path{_src_addr, _dst_addr}, std::move(data)};
    }

    bool IPPacket::load(const uint8_t* buf, size_t len)
    {
        if (len < MIN_PACKET_SIZE)
            return false;

        _buf.clear();
        _buf.resize(len);
        std::memcpy(_buf.data(), buf, len);

        _init_internals();

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

        _init_internals();

        return true;
    }

    std::vector<uint8_t> IPPacket::steal_buffer() &&
    {
        return std::move(_buf);
    }

    std::string IPPacket::steal_payload() &&
    {
        auto ret = to_string();
        _buf.clear();
        return ret;
    }

    std::vector<uint8_t> IPPacket::give_buffer()
    {
        return {_buf};
    }

    std::string IPPacket::to_string()
    {
        return {reinterpret_cast<const char*>(data()), size()};
    }

    std::string IPPacket::info_line() const
    {
        return "IPPacket:[src={} | dest={} | size={}]"_format(_src_addr, _dst_addr, size());
    }

}  // namespace llarp
