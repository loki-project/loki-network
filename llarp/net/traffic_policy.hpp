#pragma once

#include <llarp/address/ip_packet.hpp>
#include <llarp/address/ip_range.hpp>

#include <oxenc/bt.h>

#include <set>

namespace llarp::net
{
    // Copied over from llarp/net/ip_packet_old.hpp...
    // TODO: do we fucking need this?
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

    /// information about an IP protocol
    struct ProtocolInfo
    {
        /// ip protocol byte of this protocol
        IPProtocol protocol;

        /// the layer 3 port IN HOST ORDER FFS
        std::optional<uint16_t> port;

        ProtocolInfo(std::string buf);

        void bt_encode(oxenc::bt_list_producer& btlp) const;

        void bt_decode(oxenc::bt_list_consumer& btlc);

        bool bt_decode(std::string_view buf);

        nlohmann::json ExtractStatus() const;

        /// returns true if an ip packet looks like it matches this protocol info
        /// returns false otherwise
        bool matches_packet_proto(const IPPacket& pkt) const;

        bool operator<(const ProtocolInfo& other) const
        {
            return std::tie(protocol, port) < std::tie(other.protocol, other.port);
        }

        ProtocolInfo() = default;

        explicit ProtocolInfo(std::string_view spec);
    };

    /// information about what traffic an endpoint will carry
    struct TrafficPolicy
    {
        /// ranges that are explicitly allowed
        std::set<IPRange> ranges;

        /// protocols that are explicity allowed
        std::set<ProtocolInfo> protocols;

        void bt_encode(oxenc::bt_dict_producer&& btdp) const;

        void bt_decode(oxenc::bt_dict_consumer&& btdc);

        bool bt_decode(std::string_view buf);
        nlohmann::json ExtractStatus() const;

        /// returns true if we allow the traffic in this ip packet
        /// returns false otherwise
        bool allow_ip_traffic(const IPPacket& pkt);
    };
}  // namespace llarp::net
