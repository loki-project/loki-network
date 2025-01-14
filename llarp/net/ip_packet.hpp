#pragma once

#include "ip_headers.hpp"
#include "policy.hpp"

#include <llarp/util/buffer.hpp>
#include <llarp/util/formattable.hpp>
#include <llarp/util/time.hpp>

namespace llarp
{
    inline constexpr size_t MAX_PACKET_SIZE{1500};
    inline constexpr size_t MIN_PACKET_SIZE{20};

    struct IPPacket;

    // Typedef for packets being transmitted between lokinet instances
    using NetworkPacket = oxen::quic::Packet;

    using net_pkt_hook = std::function<void(NetworkPacket&& pkt)>;
    using ip_pkt_hook = std::function<void(IPPacket)>;

    /** IPPacket
        This class encapsulates the functionalities and attributes required for data transmission between the local
        lokinet instance and the surrounding IP landscape. As data enters lokinet from the device/internet/etc, it is
        transmitted across the network as a NetworkPacket via QUIC. As it exits lokinet to the device/internet/etc, it
        is constructed into an IPPacket.

        This allows for necessary functionalities at the junction that data is entering and exiting the local lokinet
        instance. For example

    */
    struct IPPacket
    {
      private:
        std::vector<uint8_t> _buf{};

        ip_header* _header{};
        ipv6_header* _v6_header{};

        oxen::quic::Address _src_addr{};
        oxen::quic::Address _dst_addr{};

        bool _is_v4{true};
        bool _is_udp{false};

        net::IPProtocol _proto{};

        void _init_internals();

      public:
        IPPacket() : IPPacket{size_t{0}} {}
        explicit IPPacket(size_t sz);
        explicit IPPacket(bstring_view data);
        explicit IPPacket(std::vector<uint8_t>&& data);
        explicit IPPacket(const uint8_t* buf, size_t len);

        static IPPacket from_netpkt(NetworkPacket pkt);
        static std::optional<IPPacket> from_buffer(const uint8_t* buf, size_t len);

        NetworkPacket make_netpkt() &&;

        // TESTNET: debug methods
        // uint16_t checksum() const { return _is_v4 ? header()->checksum : 0; }

        bool is_ipv4() const { return _is_v4; }

        net::IPProtocol protocol() const { return _proto; }

        const oxen::quic::Address& source() const { return _src_addr; }

        uint16_t source_port() { return source().port(); }

        ipv4 source_ipv4() { return _src_addr.to_ipv4(); }

        ipv6 source_ipv6() { return _src_addr.to_ipv6(); }

        const oxen::quic::Address& destination() const { return _dst_addr; }

        uint16_t dest_port() { return destination().port(); }

        ipv4 dest_ipv4() const { return _dst_addr.to_ipv4(); }

        ipv6 dest_ipv6() const { return _dst_addr.to_ipv6(); }

        ip_header* header() { return _header; }

        const ip_header* header() const { return reinterpret_cast<const ip_header*>(_header); }

        ipv6_header* v6_header() { return _v6_header; }

        const ipv6_header* v6_header() const { return reinterpret_cast<const ipv6_header*>(_v6_header); }

        std::optional<std::pair<const char*, size_t>> l4_data() const;

        void clear_addresses()
        {
            if (_is_v4)
                return update_ipv4_address(ipv4{}, ipv4{});
            return update_ipv6_address(ipv6{}, ipv6{});
        }

        void update_ipv4_address(ipv4 src, ipv4 dst);

        void update_ipv6_address(ipv6 src, ipv6 dst, std::optional<uint32_t> flowlabel = std::nullopt);

        std::optional<IPPacket> make_icmp_unreachable() const;

        uint8_t* data() { return _buf.data(); }

        const uint8_t* data() const { return _buf.data(); }

        size_t size() const { return _buf.size(); }

        bool empty() const { return _buf.empty(); }

        bool load(const uint8_t* buf, size_t len);

        // takes posession of the data
        bool take(std::vector<uint8_t> data);

        // steals posession of the underlying data, and can only be used in an r-value context
        std::vector<uint8_t> steal_buffer() &&;

        std::string steal_payload() &&;

        // gives a copy of the underlying data
        std::vector<uint8_t> give_buffer();

        std::string_view view() const { return {reinterpret_cast<const char*>(data()), size()}; }

        bstring_view bview() const { return {reinterpret_cast<const std::byte*>(data()), size()}; }

        ustring_view uview() const { return {data(), size()}; }

        std::string to_string() const;

        std::string info_line() const;
    };

}  // namespace llarp
