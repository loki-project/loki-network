#include "utils.hpp"

namespace llarp
{
    static auto logcat = log::Cat("Address-utils");

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

    uint32_t ipv4_checksum_magic(const uint8_t *buf, uint16_t len)
    {
        uint16_t odd{1}, result{0};

        odd &= (unsigned long)buf;

        if (odd)
        {
            result += oxenc::little_endian ? (*buf << 8) : *buf;
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

    uint16_t checksum_ipv4(const void *header, uint8_t header_len)
    {
        return ~ipv4_checksum_magic(static_cast<const uint8_t *>(header), header_len * 4);
    }

    uint32_t tcpudp_checksum_ipv4(uint32_t src, uint32_t dest, uint32_t len, uint8_t proto, uint32_t sum)
    {
        auto _sum = static_cast<uint64_t>(sum);

        _sum += src;
        _sum += dest;

        _sum += oxenc::big_endian ? proto + len : (proto + len) << 8;

        return from_64_to_32(_sum);
    }

    uint16_t ipv6_checksum_magic(
        const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint8_t proto, uint32_t csum)
    {
        uint32_t sum = csum;

        for (size_t i = 0; i < 4; ++i)
        {
            auto val = static_cast<uint32_t>(saddr->s6_addr32[i]);
            sum += val;
            sum += (sum < val);
        }

        for (size_t i = 0; i < 4; ++i)
        {
            auto val = static_cast<uint32_t>(daddr->s6_addr32[i]);
            sum += val;
            sum += (sum < val);
        }

        uint32_t ulen = htonl(len);
        uint32_t uproto = htonl(proto);

        sum += ulen;
        sum += (sum < ulen);

        sum += uproto;
        sum += (sum < uproto);

        return fold_csum(sum);
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
