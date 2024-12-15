#pragma once

#include <llarp/util/formattable.hpp>

#include <oxen/quic.hpp>

namespace llarp
{
    using ipv4 = oxen::quic::ipv4;
    using ipv6 = oxen::quic::ipv6;
    using ip_v = std::variant<ipv4, ipv6>;
    using ipv4_range = oxen::quic::ipv4_range;
    using ipv6_range = oxen::quic::ipv6_range;
    using ipv4_net = oxen::quic::ipv4_net;
    using ipv6_net = oxen::quic::ipv6_net;
    using ip_net_v = std::variant<ipv4_net, ipv6_net>;

    namespace concepts
    {
        template <typename ip_t>
        concept IPType = std::is_same_v<ip_t, ipv4> || std::is_same_v<ip_t, ipv6>;

        template <typename ip_range_t>
        concept IPRangeType = std::is_same_v<ip_range_t, ipv4_net> || std::is_same_v<ip_range_t, ipv6_net>;
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
        uint32_t get_flowlabel() const { return ntohl(preamble.flowlabel & htonl(ipv6_flowlabel_mask)); }

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
