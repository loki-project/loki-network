#pragma once

#include "net.hpp"

#include <llarp/util/buffer.hpp>
#include <llarp/util/time.hpp>

#include <oxenc/endian.h>

#include <memory>
#include <utility>

namespace llarp::net
{
    struct ip_header_le
    {
        uint8_t ihl : 4;
        uint8_t version : 4;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };

    struct ip_header_be
    {
        uint8_t version : 4;
        uint8_t ihl : 4;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
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
        llarp::nuint32_t FlowLabel() const;

        /// put 20 bit truncated flow label network order
        void FlowLabel(llarp::nuint32_t label);
    };

    static_assert(sizeof(ipv6_header) == 40);

    /// "well known" ip protocols
    /// TODO: extend this to non "well known values"
    enum class IPProtocol : uint8_t
    {
        ICMP = 0x01,
        IGMP = 0x02,
        IPIP = 0x04,
        TCP = 0x06,
        UDP = 0x11,
        GRE = 0x2F,
        ICMP6 = 0x3A,
        OSFP = 0x59,
        PGM = 0x71,
    };

    /// get string representation of this protocol
    /// throws std::invalid_argument if we don't know the name of this ip protocol
    std::string IPProtocolName(IPProtocol proto);

    /// parse a string to an ip protocol
    /// throws std::invalid_argument if cannot be parsed
    IPProtocol ParseIPProtocol(std::string data);

    /// an Packet
    struct IP_packet_deprecated
    {
        static constexpr size_t _max_size = 1500;
        llarp_time_t timestamp;
        std::vector<uint8_t> _buf;

       public:
        IP_packet_deprecated() : IP_packet_deprecated{size_t{}}
        {}
        /// create an ip packet buffer of all zeros of size sz
        explicit IP_packet_deprecated(size_t sz);
        /// create an ip packet from a view
        explicit IP_packet_deprecated(byte_view_t);
        /// create an ip packet from a vector we then own
        IP_packet_deprecated(std::vector<uint8_t>&&);

        ~IP_packet_deprecated() = default;

        static constexpr size_t MaxSize = _max_size;
        static constexpr size_t MinSize = 20;

        [[deprecated("deprecated because of llarp_buffer_t")]] static IP_packet_deprecated UDP(
            nuint32_t srcaddr, nuint16_t srcport, nuint32_t dstaddr, nuint16_t dstport, const llarp_buffer_t& data)
        {
            return make_udp(srcaddr, srcport, dstaddr, dstport, data.copy());
        }

        static IP_packet_deprecated make_udp(
            net::ipaddr_t srcaddr,
            net::port_t srcport,
            net::ipaddr_t dstaddr,
            net::port_t dstport,
            std::vector<uint8_t> udp_body);

        static inline IP_packet_deprecated make_udp(
            SockAddr_deprecated src, SockAddr_deprecated dst, std::variant<OwnedBuffer, std::vector<uint8_t>> udp_body)
        {
            if (auto* vec = std::get_if<std::vector<uint8_t>>(&udp_body))
                return make_udp(src.getIP(), src.port(), dst.getIP(), dst.port(), std::move(*vec));
            if (auto* buf = std::get_if<OwnedBuffer>(&udp_body))
                return make_udp(src, dst, buf->copy());
            return net::IP_packet_deprecated{size_t{}};
        }

        inline bool Load(const llarp_buffer_t& buf)
        {
            _buf = buf.copy();
            if (size() >= MinSize)
                return true;
            _buf.resize(0);
            return false;
        }

        inline llarp_buffer_t ConstBuffer() const
        {
            return llarp_buffer_t{_buf};
        }

        /// steal the underlying vector
        inline std::vector<uint8_t> steal()
        {
            std::vector<uint8_t> buf;
            buf.resize(0);
            std::swap(_buf, buf);
            return buf;
        }

        inline std::string to_string()
        {
            return {reinterpret_cast<const char*>(_buf.data()), _buf.size()};
        }

        inline std::string_view to_view()
        {
            return {reinterpret_cast<const char*>(_buf.data()), _buf.size()};
        }

        inline uint8_t* data()
        {
            return _buf.data();
        }

        inline const uint8_t* data() const
        {
            return _buf.data();
        }

        constexpr size_t capacity() const
        {
            return _max_size;
        }

        inline size_t size() const
        {
            return _buf.size();
        }

        inline bool empty() const
        {
            return _buf.empty();
        }

        byte_view_t view() const;

        struct CompareSize
        {
            bool operator()(const IP_packet_deprecated& left, const IP_packet_deprecated& right)
            {
                return left.size() < right.size();
            }
        };

        struct CompareOrder
        {
            bool operator()(const IP_packet_deprecated& left, const IP_packet_deprecated& right)
            {
                return left.timestamp < right.timestamp;
            }
        };

        inline ip_header* Header()
        {
            return reinterpret_cast<ip_header*>(data());
        }

        inline const ip_header* Header() const
        {
            return reinterpret_cast<const ip_header*>(data());
        }

        inline ipv6_header* HeaderV6()
        {
            return reinterpret_cast<ipv6_header*>(data());
        }

        inline const ipv6_header* HeaderV6() const
        {
            return reinterpret_cast<const ipv6_header*>(data());
        }

        inline int Version() const
        {
            return Header()->version;
        }

        inline uint8_t protocol() const
        {
            if (IsV4())
                return Header()->protocol;
            return HeaderV6()->protocol;
        }

        inline bool IsV4() const
        {
            return Version() == 4;
        }

        inline bool IsV6() const
        {
            return Version() == 6;
        }

        auto ServiceProtocol() const;

        huint128_t srcv6() const;

        huint128_t dstv6() const;

        huint32_t srcv4() const;

        huint32_t dstv4() const;

        huint128_t src4to6() const;

        huint128_t dst4to6() const;

        huint128_t src4to6Lan() const;

        huint128_t dst4to6Lan() const;

        SockAddr_deprecated src() const;

        SockAddr_deprecated dst() const;

        /// get destination port if applicable
        std::optional<nuint16_t> DstPort() const;

        /// get source port if applicable
        std::optional<nuint16_t> SrcPort() const;

        /// get pointer and size of layer 4 data
        std::optional<std::pair<const char*, size_t>> L4Data() const;

        inline std::optional<OwnedBuffer> L4OwnedBuffer() const
        {
            if (auto data = L4Data())
                return OwnedBuffer{reinterpret_cast<const uint8_t*>(data->first), data->second};
            return std::nullopt;
        }

        void UpdateIPv4Address(nuint32_t src, nuint32_t dst);

        void UpdateIPv6Address(huint128_t src, huint128_t dst, std::optional<nuint32_t> flowlabel = std::nullopt);

        /// set addresses to zero and recacluate checksums
        void ZeroAddresses(std::optional<nuint32_t> flowlabel = std::nullopt);

        /// zero out source address
        void ZeroSourceAddress(std::optional<nuint32_t> flowlabel = std::nullopt);

        /// make an icmp unreachable reply packet based of this ip packet
        std::optional<IP_packet_deprecated> MakeICMPUnreachable() const;

        std::function<void(net::IP_packet_deprecated)> reply;
    };

    /// generate ip checksum
    uint16_t ipchksum(const uint8_t* buf, size_t sz, uint32_t sum = 0);

}  // namespace llarp::net
