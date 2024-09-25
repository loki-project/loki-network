#pragma once

#include <llarp/util/formattable.hpp>

#include <oxen/quic.hpp>

namespace llarp
{
    using ipv4 = oxen::quic::ipv4;
    using ipv6 = oxen::quic::ipv6;
    using ip_v = std::variant<ipv4, ipv6>;
    using ipv4_range = oxen::quic::ipv4_net;
    using ipv6_range = oxen::quic::ipv6_net;
    using ip_range_v = std::variant<ipv4_range, ipv6_range>;

    namespace concepts
    {
        template <typename ip_t>
        concept IPType = std::is_same_v<ip_t, ipv4> || std::is_same_v<ip_t, ipv6>;

        template <typename ip_range_t>
        concept IPRangeType = std::is_same_v<ip_range_t, ipv4_range> || std::is_same_v<ip_range_t, ipv6_range>;
    }  // namespace concepts

    using KeyedAddress = oxen::quic::RemoteAddress;

    inline constexpr uint32_t ipv6_flowlabel_mask = 0b0000'0000'0000'1111'1111'1111'1111'1111;

    inline constexpr size_t ICMP_HEADER_SIZE{8};

    // Compares the given ip variant against a quic address
    // Returns:
    //  - true : ip == address
    //  - false : ip != address
    // Error:
    //  - throws : ip and address are mismatched ipv4 vs ipv6
    inline bool ip_equals_address(const ip_v& ip, const oxen::quic::Address& addr, bool compare_v4)
    {
        if (compare_v4 and std::holds_alternative<ipv4>(ip))
            return std::get<ipv4>(ip) == addr.to_ipv4();

        if (not compare_v4 and std::holds_alternative<ipv6>(ip))
            return std::get<ipv6>(ip) == addr.to_ipv6();

        throw std::invalid_argument{
            "Failed to compare ip variant in desired {} scheme!"_format(compare_v4 ? "ipv4" : "ipv6")};
    }

    struct ip_header_le
    {
        uint8_t header_len : 4;
        uint8_t version : 4;
        uint8_t service_type;
        uint16_t total_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src;
        uint32_t dest;
    };

    struct ip_header_be
    {
        uint8_t version : 4;
        uint8_t header_len : 4;
        uint8_t service_type;
        uint16_t total_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src;
        uint32_t dest;
    };

    using ip_header = std::conditional_t<oxenc::little_endian, ip_header_le, ip_header_be>;

    static_assert(sizeof(ip_header) == 20);

    struct ipv6_header_preamble_le
    {
        unsigned char pad_small : 4;
        unsigned char version : 4;
        uint8_t pad[3];
    };

    struct ipv6_header_preamble_be
    {
        unsigned char version : 4;
        unsigned char pad_small : 4;
        uint8_t pad[3];
    };

    using ipv6_header_preamble =
        std::conditional_t<oxenc::little_endian, ipv6_header_preamble_le, ipv6_header_preamble_be>;

    static_assert(sizeof(ipv6_header_preamble) == 4);

    struct ipv6_header
    {
        union
        {
            ipv6_header_preamble preamble;
            uint32_t flowlabel;
        } preamble;

        uint16_t payload_len;
        uint8_t protocol;
        uint8_t hoplimit;
        in6_addr srcaddr;
        in6_addr dstaddr;

        /// Returns the flowlabel (stored in network order) in HOST ORDER
        uint32_t set_flowlabel() const { return ntohl(preamble.flowlabel & htonl(ipv6_flowlabel_mask)); }

        /// Sets a flowlabel in network order. Takes in a label in HOST ORDER
        void set_flowlabel(uint32_t label)
        {
            // the ipv6 flow label is the last 20 bits in the first 32 bits of the header
            preamble.flowlabel =
                (htonl(ipv6_flowlabel_mask) & htonl(label)) | (preamble.flowlabel & htonl(~ipv6_flowlabel_mask));
        }
    };

    static_assert(sizeof(ipv6_header) == 40);

}  //   namespace llarp

namespace std
{
    template <>
    struct hash<llarp::ipv4>
    {
        size_t operator()(const llarp::ipv4& obj) const { return hash<decltype(obj.addr)>{}(obj.addr); }
    };

    template <>
    struct hash<llarp::ipv6>
    {
        size_t operator()(const llarp::ipv6& obj) const
        {
            auto h = hash<decltype(obj.hi)>{}(obj.hi);
            h ^= hash<decltype(obj.lo)>{}(obj.lo) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };

    template <>
    struct hash<llarp::ip_v>
    {
        size_t operator()(const llarp::ip_v& obj) const
        {
            if (auto maybe_v4 = std::get_if<llarp::ipv4>(&obj))
                return hash<llarp::ipv4>{}(*maybe_v4);

            return hash<llarp::ipv6>{}(std::get<llarp::ipv6>(obj));
        }
    };
}  //  namespace std
