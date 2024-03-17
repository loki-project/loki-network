#include "ip_packet.hpp"

#include "utils.hpp"

#include <llarp/util/buffer.hpp>
#include <llarp/util/time.hpp>

#include <oxenc/endian.h>

#include <cstddef>
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
    {
        _init_internals();
    }

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

    void IPPacket::_init_internals()
    {
        _header = reinterpret_cast<ip_header*>(data());
        _v6_header = reinterpret_cast<ipv6_header*>(data());

        _is_v4 = _header->protocol == uint8_t{4};
        _is_udp = _header->protocol == uint8_t{17};

        uint16_t src_port =
            (_is_udp) ? *reinterpret_cast<uint16_t*>(data() + (static_cast<ptrdiff_t>(_header->header_len) * 4)) : 0;
        uint16_t dest_port = (_is_udp)
            ? *reinterpret_cast<uint16_t*>(data() + (static_cast<ptrdiff_t>(_header->header_len) * 4) + 2)
            : 0;

        if (_is_v4)
        {
            auto src = in_addr{_header->src};
            auto dest = in_addr{_header->dest};

            _src_addr.set_addr(&src);
            _dst_addr.set_addr(&dest);
        }
        else
        {
            _src_addr.set_addr(&_v6_header->srcaddr);
            _dst_addr.set_addr(&_v6_header->dstaddr);
        }

        _src_addr.set_port(src_port);
        _dst_addr.set_port(dest_port);
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

        auto old_src = ipv4{_header->src};
        auto old_dest = ipv4{_header->dest};

        auto* buf = data();
        auto sz = size();

        // Header length is divided by 4 to indicate the number of 32 bit words; multiplying
        // by 4 returns the size
        auto header_size = static_cast<size_t>(_header->header_len * 4);

        if (header_size <= sz)
        {
            auto pld = buf + header_size;
            auto psz = sz - header_size;

            auto fragoff = static_cast<size_t>((ntohs(_header->frag_off) & 0x1Fff) * 8);

            switch (_header->protocol)
            {
                case 6:  // TCP
                    deltaChecksumIPv4TCP(pld, psz, fragoff, 16, old_src, old_dest, old_src, old_dest);
                    break;
                case 17:   // UDP
                case 136:  // UDP-Lite - same checksum place, same 0->0xFFff condition
                    deltaChecksumIPv4UDP(pld, psz, fragoff, old_src, old_dest, old_src, old_dest);
                    break;
                case 33:  // DCCP
                    deltaChecksumIPv4TCP(pld, psz, fragoff, 6, old_src, old_dest, old_src, old_dest);
                    break;
            }
        }

        // IPv4 checksum
        auto v4chk = (uint16_t*)&(_header->checksum);
        *v4chk = deltaIPv4Checksum(*v4chk, old_src, old_dest, old_src, old_dest);

        // write new IP addresses
        _header->src = nSrcIP.n;
        _header->dest = nDstIP.n;
    }

    void IPPacket::update_ipv6_address(ipv6 src, ipv6 dst, std::optional<uint32_t> flowlabel)
    {
        const size_t ihs = 4 + 4 + 16 + 16;
        const auto sz = size();
        // XXX should've been checked at upper level?
        if (sz <= ihs)
            return;

        auto hdr = HeaderV6();
        if (flowlabel.has_value())
        {
            // set flow label if desired
            hdr->FlowLabel(*flowlabel);
        }

        const auto oldSrcIP = hdr->srcaddr;
        const auto oldDstIP = hdr->dstaddr;
        const uint32_t* oSrcIP = in6_uint32_ptr(oldSrcIP);
        const uint32_t* oDstIP = in6_uint32_ptr(oldDstIP);

        // IPv6 address
        hdr->srcaddr = HUIntToIn6(src);
        hdr->dstaddr = HUIntToIn6(dst);
        const uint32_t* nSrcIP = in6_uint32_ptr(hdr->srcaddr);
        const uint32_t* nDstIP = in6_uint32_ptr(hdr->dstaddr);

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

        switch (nextproto)
        {
            case 6:  // TCP
                deltaChecksumIPv6TCP(pld, psz, fragoff, 16, oSrcIP, oDstIP, nSrcIP, nDstIP);
                break;
            case 17:   // UDP
            case 136:  // UDP-Lite - same checksum place, same 0->0xFFff condition
                deltaChecksumIPv6UDP(pld, psz, fragoff, oSrcIP, oDstIP, nSrcIP, nDstIP);
                break;
            case 33:  // DCCP
                deltaChecksumIPv6TCP(pld, psz, fragoff, 6, oSrcIP, oDstIP, nSrcIP, nDstIP);
                break;
        }
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
            std::copy_n(data(), ip_hdr_sz + ICMP_HEADER_SIZE, itr);
            itr += ip_hdr_sz + ICMP_HEADER_SIZE;
            // calculate checksum of ip header
            _header->checksum = ipchksum(pkt.data(), ip_hdr_sz);
            const auto icmp_size = std::distance(icmp_begin, itr);
            // calculate icmp checksum
            *checksum = ipchksum(icmp_begin, icmp_size);
            return pkt;
        }
        return std::nullopt;
    }

    IPPacket IPPacket::from_udp(UDPPacket pkt)
    {
        auto& data = pkt.data;
        return IPPacket{reinterpret_cast<const unsigned char*>(data.data()), data.size()};
    }

    UDPPacket IPPacket::make_udp()
    {
        return UDPPacket{oxen::quic::Path{_src_addr, _dst_addr}, bview()};
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
