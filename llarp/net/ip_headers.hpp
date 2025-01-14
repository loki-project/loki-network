#pragma once

#include "utils.hpp"

#include <netinet/ip6.h>

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
        uint16_t total_len;  // entire packet size
        uint16_t id;
        uint16_t frag_off;  // fragmentation offset
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src;
        uint32_t dest;
    };

    static_assert(sizeof(ip_header) == 20);

    // TODO: WIP
    //     struct ipv6_header2
    //     {
    //       private:
    //         std::array<uint8_t, 4> preamble;

    // // #if __BYTE_ORDER == __LITTLE_ENDIAN
    // //         uint32_t flow_label : 20;
    // //         uint8_t traffic_class;
    // //         uint8_t version : 4;
    // // #else
    // //         uint8_t version : 4;
    // //         uint8_t traffic_class : 8;
    // //         uint32_t flow_label : 20;
    // // #endif
    //         uint16_t pload_len; // payload length
    //         uint8_t nxt_hdr;    // next header (protocol)
    //         uint8_t hop_limit;
    //         in6_addr src;
    //         in6_addr dest;

    //       public:

    //     };

    //     static_assert(sizeof(ipv6_header2) == 40);

    struct ipv6_header
    {
        union
        {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            unsigned char pad_small : 4;
            unsigned char version : 4;
#else
            unsigned char version : 4;
            unsigned char pad_small : 4;
#endif
            uint8_t pad[3];
            uint32_t flowlabel;
        } preamble;

        uint16_t payload_len;
        uint8_t protocol;
        uint8_t hoplimit;
        in6_addr src;
        in6_addr dest;

        /// Returns the flowlabel (stored in network order) in HOST ORDER
        uint32_t get_flowlabel() const { return oxenc::big_to_host(preamble.flowlabel & htonl(ipv6_flowlabel_mask)); }

        /// Sets a flowlabel in network order. Takes in a label in HOST ORDER
        void set_flowlabel(uint32_t label)
        {
            // the ipv6 flow label is the last 20 bits in the first 32 bits of the header
            preamble.flowlabel =
                (htonl(ipv6_flowlabel_mask) & htonl(label)) | (preamble.flowlabel & htonl(~ipv6_flowlabel_mask));
        }
    };

    static_assert(sizeof(ipv6_header) == 40);

    /** TODO: for mobile ipv6, implement ipv6 routing headers
     */

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
        uint16_t src;    // src addr or port
        uint16_t dest;   // dst addr or port
        uint32_t seqno;  // sequence number
        uint32_t ack;    // ack number
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t xx : 4;        // unused/reserved
        uint8_t data_off : 4;  // data offset
#else
        uint8_t data_off : 4;  // data offset
        uint8_t xx : 4;        // unused/reserved
#endif
        uint8_t flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urg_ptr;  // urgent ptr
    };

    struct udp_header
    {
        uint16_t src;
        uint16_t dest;
        uint16_t len;  // datagram length
        uint16_t checksum;
    };

}  // namespace llarp
