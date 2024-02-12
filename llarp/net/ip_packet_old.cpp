#include "ip_packet_old.hpp"

#include "ip.hpp"

#include <llarp/constants/net.hpp>
#include <llarp/service/types.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/str.hpp>
#ifndef _WIN32
#include <netinet/in.h>
#endif

#include <oxenc/endian.h>

#include <algorithm>

namespace llarp::net
{
    constexpr uint32_t ipv6_flowlabel_mask = 0b0000'0000'0000'1111'1111'1111'1111'1111;

    /// get 20 bit truncated flow label in network order
    llarp::nuint32_t ipv6_header::FlowLabel() const
    {
        return llarp::nuint32_t{preamble.flowlabel & htonl(ipv6_flowlabel_mask)};
    }

    /// put 20 bit truncated flow label network order
    void ipv6_header::FlowLabel(llarp::nuint32_t label)
    {
        // the ipv6 flow label is the last 20 bits in the first 32 bits of the header
        preamble.flowlabel =
            (htonl(ipv6_flowlabel_mask) & label.n) | (preamble.flowlabel & htonl(~ipv6_flowlabel_mask));
    };

    std::string IPProtocolName(IPProtocol proto)
    {
        if (const auto* ent = ::getprotobynumber(static_cast<uint8_t>(proto)))
        {
            return ent->p_name;
        }
        throw std::invalid_argument{
            "cannot determine protocol name for ip proto '" + std::to_string(static_cast<int>(proto)) + "'"};
    }

    IPProtocol ParseIPProtocol(std::string data)
    {
        if (const auto* ent = ::getprotobyname(data.c_str()))
        {
            return static_cast<IPProtocol>(ent->p_proto);
        }
        if (starts_with(data, "0x"))
        {
            if (const int intVal = std::stoi(data.substr(2), nullptr, 16); intVal > 0)
                return static_cast<IPProtocol>(intVal);
        }
        throw std::invalid_argument{"no such ip protocol: '" + data + "'"};
    }
    inline static uint32_t* in6_uint32_ptr(in6_addr& addr)
    {
        return (uint32_t*)addr.s6_addr;
    }

    inline static const uint32_t* in6_uint32_ptr(const in6_addr& addr)
    {
        return (uint32_t*)addr.s6_addr;
    }

    huint128_t IP_packet_deprecated::srcv6() const
    {
        if (IsV6())
            return In6ToHUInt(HeaderV6()->srcaddr);

        return ExpandV4(srcv4());
    }

    huint128_t IP_packet_deprecated::dstv6() const
    {
        if (IsV6())
            return In6ToHUInt(HeaderV6()->dstaddr);

        return ExpandV4(dstv4());
    }

    IP_packet_deprecated::IP_packet_deprecated(byte_view_t view)
    {
        if (view.size() < MinSize)
        {
            _buf.resize(0);
            return;
        }
        _buf.resize(view.size());
        std::copy_n(view.data(), size(), data());
    }

    IP_packet_deprecated::IP_packet_deprecated(size_t sz)
    {
        if (sz and sz < MinSize)
            throw std::invalid_argument{"buffer size is too small to hold an ip packet"};
        _buf.resize(sz);
    }

    SockAddr_deprecated IP_packet_deprecated::src() const
    {
        const auto port = SrcPort().value_or(net::port_t{});

        if (IsV4())
            return SockAddr_deprecated{ToNet(srcv4()), port};
        else
            return SockAddr_deprecated{ToNet(srcv6()), port};
    }

    SockAddr_deprecated IP_packet_deprecated::dst() const
    {
        auto port = *DstPort();
        if (IsV4())
            return SockAddr_deprecated{ToNet(dstv4()), port};
        else
            return SockAddr_deprecated{ToNet(dstv6()), port};
    }

    IP_packet_deprecated::IP_packet_deprecated(std::vector<uint8_t>&& stolen) : _buf{stolen}
    {
        if (size() < MinSize)
            _buf.resize(0);
    }

    auto IP_packet_deprecated::ServiceProtocol() const
    {
        if (IsV4())
            return service::ProtocolType::TrafficV4;
        if (IsV6())
            return service::ProtocolType::TrafficV6;

        return service::ProtocolType::Control;
    }

    byte_view_t IP_packet_deprecated::view() const
    {
        return byte_view_t{data(), size()};
    }

    std::optional<nuint16_t> IP_packet_deprecated::DstPort() const
    {
        switch (IPProtocol{Header()->protocol})
        {
            case IPProtocol::TCP:
            case IPProtocol::UDP:
                return nuint16_t{*reinterpret_cast<const uint16_t*>(data() + (Header()->ihl * 4) + 2)};
            default:
                return std::nullopt;
        }
    }

    std::optional<nuint16_t> IP_packet_deprecated::SrcPort() const
    {
        IPProtocol proto{Header()->protocol};
        switch (proto)
        {
            case IPProtocol::TCP:
            case IPProtocol::UDP:
                return nuint16_t{*reinterpret_cast<const uint16_t*>(data() + (Header()->ihl * 4))};
            default:
                return std::nullopt;
        }
    }

    huint32_t IP_packet_deprecated::srcv4() const
    {
        return huint32_t{ntohl(Header()->saddr)};
    }

    huint32_t IP_packet_deprecated::dstv4() const
    {
        return huint32_t{ntohl(Header()->daddr)};
    }

    huint128_t IP_packet_deprecated::dst4to6() const
    {
        return ExpandV4(dstv4());
    }

    huint128_t IP_packet_deprecated::src4to6() const
    {
        return ExpandV4(srcv4());
    }

    huint128_t IP_packet_deprecated::dst4to6Lan() const
    {
        return ExpandV4Lan(dstv4());
    }

    huint128_t IP_packet_deprecated::src4to6Lan() const
    {
        return ExpandV4Lan(srcv4());
    }

    uint16_t ipchksum(const uint8_t* buf, size_t sz, uint32_t sum)
    {
        while (sz > 1)
        {
            sum += *(const uint16_t*)buf;
            sz -= sizeof(uint16_t);
            buf += sizeof(uint16_t);
        }
        if (sz != 0)
        {
            uint16_t x = 0;

            *(uint8_t*)&x = *(const uint8_t*)buf;
            sum += x;
        }

        // only need to do it 2 times to be sure
        // proof: 0xFFff + 0xFFff = 0x1FFfe -> 0xFFff
        sum = (sum & 0xFFff) + (sum >> 16);
        sum += sum >> 16;

        return uint16_t((~sum) & 0xFFff);
    }

#define ADD32CS(x) ((uint32_t)(x & 0xFFff) + (uint32_t)(x >> 16))
#define SUB32CS(x) ((uint32_t)((~x) & 0xFFff) + (uint32_t)((~x) >> 16))

    static nuint16_t deltaIPv4Checksum(
        nuint16_t old_sum, nuint32_t old_src_ip, nuint32_t old_dst_ip, nuint32_t new_src_ip, nuint32_t new_dst_ip)
    {
        uint32_t sum = uint32_t(old_sum.n) + ADD32CS(old_src_ip.n) + ADD32CS(old_dst_ip.n) + SUB32CS(new_src_ip.n)
            + SUB32CS(new_dst_ip.n);

        // only need to do it 2 times to be sure
        // proof: 0xFFff + 0xFFff = 0x1FFfe -> 0xFFff
        sum = (sum & 0xFFff) + (sum >> 16);
        sum += sum >> 16;

        return nuint16_t{uint16_t(sum & 0xFFff)};
    }

    static nuint16_t deltaIPv6Checksum(
        nuint16_t old_sum,
        const uint32_t old_src_ip[4],
        const uint32_t old_dst_ip[4],
        const uint32_t new_src_ip[4],
        const uint32_t new_dst_ip[4])
    {
        /* we don't actually care in what way integers are arranged in memory
         * internally */
        /* as long as uint16 pairs are swapped in correct direction, result will
         * be correct (assuming there are no gaps in structure) */
        /* we represent 128bit stuff there as 4 32bit ints, that should be more or
         * less correct */
        /* we could do 64bit ints too but then we couldn't reuse 32bit macros and
         * that'd suck for 32bit cpus */
#define ADDN128CS(x) (ADD32CS(x[0]) + ADD32CS(x[1]) + ADD32CS(x[2]) + ADD32CS(x[3]))
#define SUBN128CS(x) (SUB32CS(x[0]) + SUB32CS(x[1]) + SUB32CS(x[2]) + SUB32CS(x[3]))
        uint32_t sum = uint32_t(old_sum.n) + ADDN128CS(old_src_ip) + ADDN128CS(old_dst_ip) + SUBN128CS(new_src_ip)
            + SUBN128CS(new_dst_ip);
#undef ADDN128CS
#undef SUBN128CS

        // only need to do it 2 times to be sure
        // proof: 0xFFff + 0xFFff = 0x1FFfe -> 0xFFff
        sum = (sum & 0xFFff) + (sum >> 16);
        sum += sum >> 16;

        return nuint16_t{uint16_t(sum & 0xFFff)};
    }

#undef ADD32CS
#undef SUB32CS

    static void deltaChecksumIPv4TCP(
        uint8_t* pld,
        size_t psz,
        size_t fragoff,
        size_t chksumoff,
        nuint32_t oSrcIP,
        nuint32_t oDstIP,
        nuint32_t nSrcIP,
        nuint32_t nDstIP)
    {
        if (fragoff > chksumoff || psz < chksumoff - fragoff + 2)
            return;

        auto check = (nuint16_t*)(pld + chksumoff - fragoff);

        *check = deltaIPv4Checksum(*check, oSrcIP, oDstIP, nSrcIP, nDstIP);
        // usually, TCP checksum field cannot be 0xFFff,
        // because one's complement addition cannot result in 0x0000,
        // and there's inversion in the end;
        // emulate that.
        if (check->n == 0xFFff)
            check->n = 0x0000;
    }

    static void deltaChecksumIPv6TCP(
        uint8_t* pld,
        size_t psz,
        size_t fragoff,
        size_t chksumoff,
        const uint32_t oSrcIP[4],
        const uint32_t oDstIP[4],
        const uint32_t nSrcIP[4],
        const uint32_t nDstIP[4])
    {
        if (fragoff > chksumoff || psz < chksumoff - fragoff + 2)
            return;

        auto check = (nuint16_t*)(pld + chksumoff - fragoff);

        *check = deltaIPv6Checksum(*check, oSrcIP, oDstIP, nSrcIP, nDstIP);
        // usually, TCP checksum field cannot be 0xFFff,
        // because one's complement addition cannot result in 0x0000,
        // and there's inversion in the end;
        // emulate that.
        if (check->n == 0xFFff)
            check->n = 0x0000;
    }

    static void deltaChecksumIPv4UDP(
        uint8_t* pld,
        size_t psz,
        size_t fragoff,
        nuint32_t oSrcIP,
        nuint32_t oDstIP,
        nuint32_t nSrcIP,
        nuint32_t nDstIP)
    {
        if (fragoff > 6 || psz < 6 + 2)
            return;

        auto check = (nuint16_t*)(pld + 6);
        if (check->n == 0x0000)
            return;  // 0 is used to indicate "no checksum", don't change

        *check = deltaIPv4Checksum(*check, oSrcIP, oDstIP, nSrcIP, nDstIP);
        // 0 is used to indicate "no checksum"
        // 0xFFff and 0 are equivalent in one's complement math
        // 0xFFff + 1 = 0x10000 -> 0x0001 (same as 0 + 1)
        // infact it's impossible to get 0 with such addition,
        // when starting from non-0 value.
        // inside deltachksum we don't invert so it's safe to skip check there
        // if(check->n == 0x0000)
        //   check->n = 0xFFff;
    }

    static void deltaChecksumIPv6UDP(
        uint8_t* pld,
        size_t psz,
        size_t fragoff,
        const uint32_t oSrcIP[4],
        const uint32_t oDstIP[4],
        const uint32_t nSrcIP[4],
        const uint32_t nDstIP[4])
    {
        if (fragoff > 6 || psz < 6 + 2)
            return;

        auto check = (nuint16_t*)(pld + 6);
        // 0 is used to indicate "no checksum", don't change
        // even tho this shouldn't happen for IPv6, handle it properly
        // we actually should drop/log 0-checksum packets per spec
        // but that should be done at upper level than this function
        // it's better to do correct thing there regardless
        // XXX or maybe we should change this function to be able to return error?
        // either way that's not a priority
        if (check->n == 0x0000)
            return;

        *check = deltaIPv6Checksum(*check, oSrcIP, oDstIP, nSrcIP, nDstIP);
        // 0 is used to indicate "no checksum"
        // 0xFFff and 0 are equivalent in one's complement math
        // 0xFFff + 1 = 0x10000 -> 0x0001 (same as 0 + 1)
        // infact it's impossible to get 0 with such addition,
        // when starting from non-0 value.
        // inside deltachksum we don't invert so it's safe to skip check there
        // if(check->n == 0x0000)
        //   check->n = 0xFFff;
    }

    void IP_packet_deprecated::UpdateIPv4Address(nuint32_t nSrcIP, nuint32_t nDstIP)
    {
        llarp::LogDebug("set src=", nSrcIP, " dst=", nDstIP);

        auto hdr = Header();

        auto oSrcIP = nuint32_t{hdr->saddr};
        auto oDstIP = nuint32_t{hdr->daddr};
        auto* buf = data();
        auto sz = size();
        // L4 checksum
        auto ihs = size_t(hdr->ihl * 4);
        if (ihs <= sz)
        {
            auto pld = buf + ihs;
            auto psz = sz - ihs;

            auto fragoff = size_t((ntohs(hdr->frag_off) & 0x1Fff) * 8);

            switch (hdr->protocol)
            {
                case 6:  // TCP
                    deltaChecksumIPv4TCP(pld, psz, fragoff, 16, oSrcIP, oDstIP, nSrcIP, nDstIP);
                    break;
                case 17:   // UDP
                case 136:  // UDP-Lite - same checksum place, same 0->0xFFff condition
                    deltaChecksumIPv4UDP(pld, psz, fragoff, oSrcIP, oDstIP, nSrcIP, nDstIP);
                    break;
                case 33:  // DCCP
                    deltaChecksumIPv4TCP(pld, psz, fragoff, 6, oSrcIP, oDstIP, nSrcIP, nDstIP);
                    break;
            }
        }

        // IPv4 checksum
        auto v4chk = (nuint16_t*)&(hdr->check);
        *v4chk = deltaIPv4Checksum(*v4chk, oSrcIP, oDstIP, nSrcIP, nDstIP);

        // write new IP addresses
        hdr->saddr = nSrcIP.n;
        hdr->daddr = nDstIP.n;
    }

    void IP_packet_deprecated::UpdateIPv6Address(huint128_t src, huint128_t dst, std::optional<nuint32_t> flowlabel)
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

    void IP_packet_deprecated::ZeroAddresses(std::optional<nuint32_t> flowlabel)
    {
        if (IsV4())
        {
            UpdateIPv4Address({0}, {0});
        }
        else if (IsV6())
        {
            UpdateIPv6Address({0}, {0}, flowlabel);
        }
    }

    void IP_packet_deprecated::ZeroSourceAddress(std::optional<nuint32_t> flowlabel)
    {
        if (IsV4())
        {
            UpdateIPv4Address({0}, xhtonl(dstv4()));
        }
        else if (IsV6())
        {
            UpdateIPv6Address({0}, dstv6(), flowlabel);
        }
    }

    std::optional<IP_packet_deprecated> IP_packet_deprecated::MakeICMPUnreachable() const
    {
        if (IsV4())
        {
            constexpr auto icmp_Header_size = 8;
            auto ip_Header_size = Header()->ihl * 4;
            auto pkt_size = (icmp_Header_size + ip_Header_size) * 2;
            net::IP_packet_deprecated pkt{static_cast<size_t>(pkt_size)};

            auto* pkt_Header = pkt.Header();
            pkt_Header->version = 4;
            pkt_Header->ihl = 0x05;
            pkt_Header->tos = 0;
            pkt_Header->check = 0;
            pkt_Header->tot_len = ntohs(pkt_size);
            pkt_Header->saddr = Header()->daddr;
            pkt_Header->daddr = Header()->saddr;
            pkt_Header->protocol = 1;  // ICMP
            pkt_Header->ttl = Header()->ttl;
            pkt_Header->frag_off = htons(0b0100000000000000);

            uint16_t* checksum;
            uint8_t* itr = pkt.data() + ip_Header_size;
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
            std::copy_n(data(), ip_Header_size + icmp_Header_size, itr);
            itr += ip_Header_size + icmp_Header_size;
            // calculate checksum of ip header
            pkt_Header->check = ipchksum(pkt.data(), ip_Header_size);
            const auto icmp_size = std::distance(icmp_begin, itr);
            // calculate icmp checksum
            *checksum = ipchksum(icmp_begin, icmp_size);
            return pkt;
        }
        return std::nullopt;
    }

    std::optional<std::pair<const char*, size_t>> IP_packet_deprecated::L4Data() const
    {
        const auto* hdr = Header();
        size_t l4_HeaderSize = 0;
        if (hdr->protocol == 0x11)
        {
            l4_HeaderSize = 8;
        }
        else
            return std::nullopt;

        // check for invalid size
        if (size() < (hdr->ihl * 4) + l4_HeaderSize)
            return std::nullopt;

        const uint8_t* ptr = data() + ((hdr->ihl * 4) + l4_HeaderSize);
        return std::make_pair(reinterpret_cast<const char*>(ptr), std::distance(ptr, data() + size()));
    }

    namespace
    {
        IP_packet_deprecated make_ip4_udp(
            net::ipv4addr_t srcaddr,
            net::port_t srcport,
            net::ipv4addr_t dstaddr,
            net::port_t dstport,
            std::vector<uint8_t> udp_data)
        {
            constexpr auto pkt_overhead = constants::udp_header_bytes + constants::ip_header_min_bytes;
            net::IP_packet_deprecated pkt{udp_data.size() + pkt_overhead};

            auto* hdr = pkt.Header();
            pkt.data()[1] = 0;
            hdr->version = 4;
            hdr->ihl = 5;
            hdr->tot_len = htons(pkt_overhead + udp_data.size());
            hdr->protocol = 0x11;  // udp
            hdr->ttl = 64;
            hdr->frag_off = htons(0b0100000000000000);

            hdr->saddr = srcaddr.n;
            hdr->daddr = dstaddr.n;

            // make udp packet
            uint8_t* ptr = pkt.data() + constants::ip_header_min_bytes;
            std::memcpy(ptr, &srcport.n, 2);
            ptr += 2;
            std::memcpy(ptr, &dstport.n, 2);
            ptr += 2;
            oxenc::write_host_as_big(static_cast<uint16_t>(udp_data.size() + constants::udp_header_bytes), ptr);
            ptr += 2;
            oxenc::write_host_as_big(uint16_t{0}, ptr);  // checksum
            ptr += 2;
            std::copy_n(udp_data.data(), udp_data.size(), ptr);

            hdr->check = 0;
            hdr->check = net::ipchksum(pkt.data(), 20);
            return pkt;
        }
    }  // namespace
    IP_packet_deprecated IP_packet_deprecated::make_udp(
        net::ipaddr_t srcaddr,
        net::port_t srcport,
        net::ipaddr_t dstaddr,
        net::port_t dstport,
        std::vector<uint8_t> udp_data)
    {
        auto getfam = [](auto&& v) {
            if (std::holds_alternative<net::ipv4addr_t>(v))
                return AF_INET;
            else if (std::holds_alternative<net::ipv6addr_t>(v))
                return AF_INET6;
            else
                return AF_UNSPEC;
        };
        auto fam = getfam(srcaddr);
        if (fam != getfam(dstaddr))
            return net::IP_packet_deprecated{size_t{}};
        if (fam == AF_INET)
        {
            return make_ip4_udp(
                *std::get_if<net::ipv4addr_t>(&srcaddr),
                srcport,
                *std::get_if<net::ipv4addr_t>(&dstaddr),
                dstport,
                std::move(udp_data));
        }
        // TODO: ipv6
        return net::IP_packet_deprecated{size_t{}};
    }
}  // namespace llarp::net
