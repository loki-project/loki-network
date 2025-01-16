#include "utils.hpp"

#include <llarp/util/logging.hpp>

namespace llarp
{
    static auto logcat = log::Cat("net-utils");

    bool ip_equals_address(const ip_v &ip, const oxen::quic::Address &addr, bool compare_v4)
    {
        if (compare_v4 and std::holds_alternative<ipv4>(ip))
            return std::get<ipv4>(ip) == addr.to_ipv4();

        if (not compare_v4 and std::holds_alternative<ipv6>(ip))
            return std::get<ipv6>(ip) == addr.to_ipv6();

        log::warning(logcat, "Failed to compare ip variant in desired ipv{} scheme!", compare_v4 ? "4" : "6");
        return false;
    }

    namespace utils
    {
        static constexpr uint32_t add_u32(uint32_t x) { return uint32_t{x & 0xFFff} + uint32_t{x >> 16}; }
        // static constexpr uint32_t add_u32(ipv4 x) { return add_u32(oxenc::host_to_big(x.addr)); }
        static uint32_t add_u32(ipv4 x) { return add_u32(oxenc::host_to_big(x.addr)); }

        static constexpr uint32_t sub_u32(uint32_t x) { return add_u32(~x); }
        // static constexpr uint32_t sub_u32(ipv4 x) { return sub_u32(oxenc::host_to_big(x.addr)); }
        static uint32_t sub_u32(ipv4 x) { return sub_u32(oxenc::host_to_big(x.addr)); }

        uint16_t ip_checksum(const uint8_t *buf, size_t sz)
        {
            uint32_t sum = 0;

            while (sz > 1)
            {
                sum += *(uint16_t *)(buf);
                sz -= sizeof(uint16_t);
                buf += sizeof(uint16_t);
            }

            if (sz != 0)
            {
                uint16_t x = 0;
                *(uint8_t *)&x = *buf;
                sum += x;
            }

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return uint16_t((~sum) & 0xFFff);
        }

        uint16_t ipv4_checksum_diff(uint16_t old_sum, uint32_t old_src, uint32_t old_dest, ipv4 new_src, ipv4 new_dest)
        {
            uint32_t sum = old_sum + add_u32(old_src) + add_u32(old_dest) + sub_u32(new_src) + sub_u32(new_dest);

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return uint16_t(sum & 0xFFff);
        }

        uint16_t ipv4_tcp_checksum_diff(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, ipv4 new_src, ipv4 new_dest)
        {
            auto new_sum = ipv4_checksum_diff(old_sum, old_src, old_dest, new_src, new_dest);
            return new_sum == 0xFFff ? 0x0000 : new_sum;
        }

        uint16_t ipv4_udp_checksum_diff(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, ipv4 new_src, ipv4 new_dest)
        {
            if (old_sum == 0x0000)
                return old_sum;

            return ipv4_checksum_diff(old_sum, old_src, old_dest, new_src, new_dest);
        }
    }  // namespace utils

    uint16_t csum_add(uint16_t csum, uint16_t rhs)
    {
        uint32_t res = csum, other = rhs;
        res += other;
        return static_cast<uint16_t>(res + (res < other));
    }

    uint16_t csum_sub(uint16_t csum, uint16_t rhs) { return csum_add(csum, ~rhs); }

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
}  //  namespace llarp
