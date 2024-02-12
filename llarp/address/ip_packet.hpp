#pragma once

#include "types.hpp"

#include <llarp/ev/types.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/formattable.hpp>
#include <llarp/util/time.hpp>

namespace llarp
{
    inline constexpr size_t MAX_PACKET_SIZE{1500};
    inline constexpr size_t MIN_PACKET_SIZE{20};

    struct IPPacket
    {
       private:
        std::vector<uint8_t> _buf;

       public:
        IPPacket() : IPPacket{size_t{0}}
        {}
        explicit IPPacket(size_t sz);
        explicit IPPacket(bstring_view data);
        explicit IPPacket(ustring_view data);
        explicit IPPacket(std::vector<uint8_t> data);
        explicit IPPacket(const uint8_t* buf, size_t len);

        static IPPacket from_udp(UDPPacket pkt);

        UDPPacket make_udp(ip src_addr, uint16_t src_port, ip dest_addr, uint16_t dest_port);

        UDPPacket make_udp(oxen::quic::Address src, oxen::quic::Address dest);

        uint8_t* data()
        {
            return _buf.data();
        }

        const uint8_t* data() const
        {
            return _buf.data();
        }

        size_t size() const
        {
            return _buf.size();
        }

        bool empty() const
        {
            return _buf.empty();
        }

        bool load(std::vector<uint8_t> data);

        bool load(const uint8_t* buf, size_t len);

        // takes posession of the data
        bool take(std::vector<uint8_t> data);

        // steals posession of the underlying data, and can only be used in an r-value context
        std::vector<uint8_t> steal() &&;

        // gives a copy of the underlying data
        std::vector<uint8_t> give();

        std::string_view view() const
        {
            return {reinterpret_cast<const char*>(data()), size()};
        }

        bstring_view bview() const
        {
            return {reinterpret_cast<const std::byte*>(data()), size()};
        }

        ustring_view uview() const
        {
            return {data(), size()};
        }

        std::string to_string();
    };

    template <>
    inline constexpr bool IsToStringFormattable<IPPacket> = true;

}  // namespace llarp
