#pragma once

#include "net.hpp"

#include <llarp/address/ip_range.hpp>

#include <oxenc/bt.h>

#include <set>

namespace llarp
{
    struct IPPacket;

    enum class protocol_flag : uint16_t
    {
        CONTROL = 1 << 0,
        IPV4 = 1 << 1,
        IPV6 = 1 << 2,
        EXIT = 1 << 3,
        AUTH = 1 << 4,
        TCP2QUIC = 1 << 5,
    };

    // TODO: WIP implementation
    struct ip_protocol
    {
        enum class type : uint8_t
        {
            ICMP = 0x01,
            IGMP = 0x02,
            IPIP = 0x04,
            TCP = 0x06,
            UDP = 0x11,
            GRE = 0x2F,
            ICMP6 = 0x3A,
            OSPF = 0x59,
            PGM = 0x71,
        };
    };

    namespace net
    {
        enum class IPProtocol : uint8_t
        {
            ICMP = 0x01,
            IGMP = 0x02,
            IPIP = 0x04,
            TCP = 0x06,
            UDP = 0x11,
            GRE = 0x2F,
            ICMP6 = 0x3A,
            OSPF = 0x59,
            PGM = 0x71,
        };

        inline constexpr auto ip_protocol_name(IPProtocol p)
        {
            switch (p)
            {
                case IPProtocol::ICMP:
                    return "ICMP"sv;
                case IPProtocol::IGMP:
                    return "IGMP"sv;
                case IPProtocol::IPIP:
                    return "IPIP"sv;
                case IPProtocol::TCP:
                    return "TCP"sv;
                case IPProtocol::UDP:
                    return "UDP"sv;
                case IPProtocol::GRE:
                    return "GRE"sv;
                case IPProtocol::ICMP6:
                    return "ICMP6"sv;
                case IPProtocol::OSPF:
                    return "OSPF"sv;
                case IPProtocol::PGM:
                    return "PGM"sv;
                default:
                    return "<NONE>"sv;
            }
        }

        /// information about an IP protocol
        struct ProtocolInfo
        {
            /// ip protocol byte of this protocol
            IPProtocol proto;

            /// the layer 3 port IN HOST ORDER FFS
            std::optional<uint16_t> port{std::nullopt};

            ProtocolInfo() = default;
            ProtocolInfo(std::string_view buf);

            void bt_encode(oxenc::bt_list_producer& btlp) const;

            void bt_decode(oxenc::bt_list_consumer& btlc);

            bool bt_decode(std::string_view buf);

            // Compares packet protocol with protocol info
            bool matches_packet_proto(const IPPacket& pkt) const;

            auto operator<=>(const ProtocolInfo& other) const
            {
                return std::tie(proto, port) <=> std::tie(other.proto, other.port);
            }

            bool operator==(const ProtocolInfo& other) const { return (*this <=> other) == 0; }

            bool operator<(const ProtocolInfo& other) const
            {
                return std::tie(proto, port) < std::tie(other.proto, other.port);
            }

            // explicit ProtocolInfo(std::string_view spec);
        };

        /// information about what exit traffic an endpoint will carry
        struct ExitPolicy
        {
            /// ranges that are explicitly allowed
            std::set<IPRange> ranges;

            /// protocols that are explicity allowed
            std::set<ProtocolInfo> protocols;

            bool empty() const { return ranges.empty() and protocols.empty(); }

            void bt_encode(oxenc::bt_dict_producer&& btdp) const;

            void bt_decode(oxenc::bt_dict_consumer&& btdc);

            bool bt_decode(std::string_view buf);

            auto operator<=>(const ExitPolicy& other) const
            {
                return std::tie(ranges, protocols) <=> std::tie(other.ranges, other.protocols);
            }

            bool operator==(const ExitPolicy& other) const { return (*this <=> other) == 0; }

            // Verifies if IPPacket traffic is allowed; return true/false
            bool allow_ip_traffic(const IPPacket& pkt) const;
        };
    }  // namespace net
}  // namespace llarp
