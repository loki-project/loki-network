#include "utils.hpp"

#include "ip_headers.hpp"

namespace llarp
{
    static auto logcat = log::Cat("address-utils");

    namespace utils
    {
        // constexpr auto IP_CSUM_OFF = offsetof(struct ip_header, checksum);
        // constexpr auto IP_DST_OFF = offsetof(struct ip_header, dest);
        // constexpr auto IP_SRC_OFF = offsetof(struct ip_header, src);
        // constexpr auto IP_PROTO_OFF = offsetof(struct ip_header, protocol);
        // constexpr auto TCP_CSUM_OFF = offsetof(struct tcp_header, checksum);
        // constexpr auto UDP_CSUM_OFF = offsetof(struct tcp_header, checksum);
        // constexpr auto IS_PSEUDO = 0x10;

        static constexpr uint32_t add_u32(uint32_t x)
        {
            return uint32_t{x & 0xFFff} + uint32_t{x >> 16};
        }

        uint16_t ip_checksum(const uint8_t *buf, size_t sz)
        {
            uint32_t sum{};

            while (sz > 1)
            {
                sum += *reinterpret_cast<const uint16_t *>(buf);
                sz -= sizeof(uint16_t);
                buf += sizeof(uint16_t);
            }
            if (sz != 0)
                sum += *reinterpret_cast<const uint16_t *>(buf);

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return static_cast<uint16_t>((~sum) & 0xFFff);
        }

        uint16_t ipv4_checksum_diff(uint16_t old_sum, ipv4 old_src, ipv4 old_dest, ipv4 new_src, ipv4 new_dest)
        {
            uint32_t sum = oxenc::host_to_big<uint32_t>(old_sum);
        }

    }  // namespace utils

    uint16_t csum_add(uint16_t csum, uint16_t rhs)
    {
        uint32_t res = csum, other = rhs;
        res += other;
        return static_cast<uint16_t>(res + (res < other));
    }

    uint16_t csum_sub(uint16_t csum, uint16_t rhs)
    {
        return csum_add(csum, ~rhs);
    }

    uint16_t from_32_to_16(uint32_t x)
    {
        /* add up 16-bit and 16-bit for 16+c bit */
        x = (x & 0xffff) + (x >> 16);
        /* add up carry.. */
        x = (x & 0xffff) + (x >> 16);
        return x;
    }

    uint32_t from_64_to_32(uint64_t x)
    {
        /* add up 32-bit and 32-bit for 32+c bit */
        x = (x & 0xffffffff) + (x >> 32);
        /* add up carry.. */
        x = (x & 0xffffffff) + (x >> 32);
        return x;
    }

    uint16_t fold_csum(uint32_t csum)
    {
        auto sum = csum;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    uint32_t ipv4_checksum_magic(const uint8_t *buf, int len)
    {
        int odd{1};
        uint16_t result{0};

        odd &= (unsigned long)buf;

        if (odd)
        {
            if constexpr (oxenc::little_endian)
                result += (*buf << 8);
            else
                result = *buf;

            --len;
            ++buf;
        }

        if (len >= 2)
        {
            if (2 & (unsigned long)buf)
            {
                result += *(unsigned short *)buf;
                len -= 2;
                buf += 2;
            }

            if (len >= 4)
            {
                const unsigned char *end = buf + ((unsigned)len & ~3);
                unsigned int carry = 0;

                do
                {
                    unsigned int w = *(unsigned int *)buf;
                    buf += 4;
                    result += carry;
                    result += w;
                    carry = (w > result);
                } while (buf < end);

                result += carry;
                result = (result & 0xffff) + (result >> 16);
            }

            if (len & 2)
            {
                result += *(unsigned short *)buf;
                buf += 2;
            }
        }

        if (len & 1)
            result += oxenc::little_endian ? *buf : (*buf << 8);

        result = from_32_to_16(result);

        if (odd)
            result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);

        return result;
    }

    uint16_t checksum_partial(const void *header, uint8_t header_len, uint16_t old_sum)
    {
        uint16_t result = ipv4_checksum_magic(reinterpret_cast<const uint8_t *>(header), header_len);

        if (result += old_sum; old_sum > result)
            result += 1;

        return result;
    }

    uint16_t checksum_ipv4(const void *header, uint8_t header_len)
    {
        return ~ipv4_checksum_magic(reinterpret_cast<const uint8_t *>(header), header_len * 4);
    }

    uint32_t tcpudp_checksum_ipv4(uint32_t src, uint32_t dest, uint32_t len, uint8_t proto, uint32_t sum)
    {
        auto csum = static_cast<uint64_t>(sum);

        csum += src;
        csum += dest;

        csum += oxenc::big_endian ? proto + len : (proto + len) << 8;

        return from_64_to_32(csum);
    }

    uint16_t ipv6_checksum_magic(
        const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint8_t proto, uint32_t sum)
    {
        uint32_t csum = sum;

        for (size_t i = 0; i < 4; ++i)
        {
            auto val = static_cast<uint32_t>(saddr->s6_addr32[i]);
            csum += val;
            csum += (csum < val);
        }

        for (size_t i = 0; i < 4; ++i)
        {
            auto val = static_cast<uint32_t>(daddr->s6_addr32[i]);
            csum += val;
            csum += (csum < val);
        }

        uint32_t ulen = htonl(len);
        uint32_t uproto = htonl(proto);

        csum += ulen;
        csum += (csum < ulen);

        csum += uproto;
        csum += (csum < uproto);

        return fold_csum(csum);
    }

    uint32_t tcp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum)
    {
        return ~ipv6_checksum_magic(saddr, daddr, len, IPPROTO_TCP, csum);
    }

    uint32_t udp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum)
    {
        return ~ipv6_checksum_magic(saddr, daddr, len, IPPROTO_UDP, csum);
    }

}  // namespace llarp
