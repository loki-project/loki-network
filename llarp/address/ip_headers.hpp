#pragma once

#include "utils.hpp"

namespace llarp
{
    struct ip_header
    {
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t header_len : 4;
        uint8_t version : 4;
#else
        uint8_t version : 4;
        uint8_t header_len : 4;
#endif
        uint8_t service_type;
        uint16_t total_len;
        uint16_t id;
        uint16_t frag_off;  // fragmentation offset
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src;
        uint32_t dest;
    };

    static_assert(sizeof(ip_header) == 20);

    enum class TCPFLAG : uint8_t
    {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PUSH = 0x08,
        ACK = 0x10,
        URG = 0x20
    };

    struct tcp_header
    {
        uint16_t src;
        uint16_t dest;
        uint32_t seqno;  // sequence number
        uint32_t ack;    // ack number
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t xx;        // unused
        uint8_t data_off;  // data offset
#else
        uint8_t data_off;  // data offset
        uint8_t xx;        // unused

#endif
        uint8_t flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urg_ptr;  // urgent ptr
    };

    struct udphdr
    {
        uint16_t src;
        uint16_t dest;
        uint16_t len;  // datagram length
        uint16_t checksum;
    };

}  // namespace llarp
