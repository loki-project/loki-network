#pragma once

#include <llarp/address/types.hpp>

namespace llarp
{
    inline constexpr uint32_t ipv6_flowlabel_mask = 0b0000'0000'0000'1111'1111'1111'1111'1111;

    inline constexpr size_t ICMP_HEADER_SIZE{8};

    // Compares the given ip variant against a quic address
    // Returns:
    //  - true : ip == address
    //  - false :
    //      - ip != address
    //      - ip and address are mismatched ipv4 vs ipv6
    bool ip_equals_address(const ip_v &ip, const oxen::quic::Address &addr, bool compare_v4);

    namespace utils
    {
        uint16_t ip_checksum(const uint8_t *buf, size_t sz);

        // Parameters:
        //  - old_sum : old checksum (NETWORK order!)
        //  - old_{src,dest} : old src and dest IP's (stored internally in HOST order!)
        //  - new_{src,dest} : new src and dest IP's (stored internally in HOST order!)
        //
        // Returns:
        //  - uint16_t : new checksum (NETWORK order!)
        uint16_t ipv4_checksum_diff(uint16_t old_sum, uint32_t old_src, uint32_t old_dest, ipv4 new_src, ipv4 new_dest);

        uint16_t ipv4_tcp_checksum_diff(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, ipv4 new_src, ipv4 new_dest);

        uint16_t ipv4_udp_checksum_diff(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, ipv4 new_src, ipv4 new_dest);

        uint16_t ipv6_checksum_diff();
    }  // namespace utils

    uint32_t tcp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);

    uint32_t udp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);

}  //  namespace llarp
