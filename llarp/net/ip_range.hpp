#pragma once

#include "ip.hpp"
#include "net_bits.hpp"

#include <llarp/util/bits.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/types.hpp>

#include <oxen/log/catlogger.hpp>
#include <oxenc/bt.h>

#include <list>
#include <optional>
#include <stdexcept>
#include <string>

namespace
{
    static auto net_cat = llarp::log::Cat("lokinet.net");
}  // namespace

namespace llarp
{
    struct IP_range_deprecated
    {
        using Addr_t = huint128_t;
        huint128_t addr = {0};
        huint128_t netmask_bits = {0};

        constexpr IP_range_deprecated()
        {}
        constexpr IP_range_deprecated(huint128_t address, huint128_t netmask)
            : addr{std::move(address)}, netmask_bits{std::move(netmask)}
        {}

        explicit IP_range_deprecated(std::string _range)
        {
            if (not FromString(_range))
                throw std::invalid_argument{"IP string '{}' cannot be parsed as IP range"_format(_range)};
        }

        static constexpr IP_range_deprecated V4MappedRange()
        {
            return IP_range_deprecated{huint128_t{0x0000'ffff'0000'0000UL}, netmask_ipv6_bits(96)};
        }

        static constexpr IP_range_deprecated FromIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t mask)
        {
            return IP_range_deprecated{net::ExpandV4(ipaddr_ipv4_bits(a, b, c, d)), netmask_ipv6_bits(mask + 96)};
        }

        static inline IP_range_deprecated FromIPv4(net::ipv4addr_t addr, net::ipv4addr_t netmask)
        {
            return IP_range_deprecated{
                net::ExpandV4(llarp::net::ToHost(addr)), netmask_ipv6_bits(bits::count_bits(netmask) + 96)};
        }

        /// return true if this iprange is in the IPv4 mapping range for containing ipv4 addresses
        constexpr bool IsV4() const
        {
            return V4MappedRange().Contains(addr);
        }

        /// get address family
        constexpr int Family() const
        {
            if (IsV4())
                return AF_INET;
            return AF_INET6;
        }

        /// return the number of bits set in the hostmask
        constexpr int HostmaskBits() const
        {
            if (IsV4())
            {
                return bits::count_bits(net::TruncateV6(netmask_bits));
            }
            return bits::count_bits(netmask_bits);
        }

        /// return true if our range and other intersect
        constexpr bool operator*(const IP_range_deprecated& other) const
        {
            return Contains(other) or other.Contains(*this);
        }

        /// return true if the other range is inside our range
        constexpr bool Contains(const IP_range_deprecated& other) const
        {
            return Contains(other.addr) and Contains(other.HighestAddr());
        }

        /// return true if ip is contained in this ip range
        constexpr bool Contains(const Addr_t& ip) const
        {
            return (addr & netmask_bits) == (ip & netmask_bits);
        }

        /// return true if we are a ipv4 range and contains this ip
        constexpr bool Contains(const huint32_t& ip) const
        {
            if (not IsV4())
                return false;
            return Contains(net::ExpandV4(ip));
        }

        inline bool Contains(const net::ipaddr_t& ip) const
        {
            return var::visit([this](auto&& ip) { return Contains(llarp::net::ToHost(ip)); }, ip);
        }

        /// get the highest address on this range
        constexpr huint128_t HighestAddr() const
        {
            return (addr & netmask_bits) + (huint128_t{1} << (128 - bits::count_bits_128(netmask_bits.h)))
                - huint128_t{1};
        }

        bool operator<(const IP_range_deprecated& other) const
        {
            auto maskedA = addr & netmask_bits, maskedB = other.addr & other.netmask_bits;
            return std::tie(maskedA, netmask_bits) < std::tie(maskedB, other.netmask_bits);
        }

        bool operator==(const IP_range_deprecated& other) const
        {
            return addr == other.addr and netmask_bits == other.netmask_bits;
        }

        std::string to_string() const
        {
            return BaseAddressString() + "/" + std::to_string(HostmaskBits());
        }

        std::string BaseAddressString() const;

        std::string NetmaskString() const;

        bool FromString(std::string str);

        void bt_encode(oxenc::bt_list_producer& btlc) const;

        bool BDecode(llarp_buffer_t* buf);

        /// Finds a free private use range not overlapping the given ranges.
        static std::optional<IP_range_deprecated> FindPrivateRange(const std::list<IP_range_deprecated>& excluding);
    };

    template <>
    constexpr inline bool IsToStringFormattable<IP_range_deprecated> = true;

}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::IP_range_deprecated>
    {
        size_t operator()(const llarp::IP_range_deprecated& range) const
        {
            const auto str = range.to_string();
            return std::hash<std::string>{}(str);
        }
    };
}  // namespace std
