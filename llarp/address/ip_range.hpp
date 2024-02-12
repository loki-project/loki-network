#pragma once

#include <llarp/util/formattable.hpp>

#include <oxen/quic.hpp>
#include <oxenc/bt_serialize.h>

namespace llarp
{
    using ipv4 = oxen::quic::ipv4;
    using ipv6 = oxen::quic::ipv6;
    using ipv4_net = oxen::quic::ipv4_net;
    using ipv6_net = oxen::quic::ipv6_net;
    using ip_net = std::variant<ipv4_net, ipv6_net>;

    struct IPRange
    {
       private:
        oxen::quic::Address _addr;
        uint8_t _mask;

        bool _is_ipv4;

        ip_net _ip;

        ip_net init_ip();

       public:
        IPRange() = default;
        explicit IPRange(std::string a, uint8_t m)
            : _addr{std::move(a), 0}, _mask{m}, _is_ipv4{_addr.is_ipv4()}, _ip{init_ip()}
        {}
        explicit IPRange(oxen::quic::Address a, uint8_t m)
            : _addr{a}, _mask{m}, _is_ipv4{_addr.is_ipv4()}, _ip{init_ip()}
        {}

        // TODO: finish this
        static std::optional<IPRange> find_private_range(const std::list<IPRange>& excluding);

        void bt_encode(oxenc::bt_list_producer& btlp) const
        {
            btlp.append(to_string());
        }

        std::string to_string() const
        {
            return _addr.to_string() + "/" + std::to_string(_mask);
        }

        static std::optional<IPRange> from_string(std::string arg);

        bool contains(const IPRange& other) const;

        bool is_ipv4() const
        {
            return _is_ipv4;
        }

        std::optional<ipv4_net> get_ipv4_net() const;

        std::optional<ipv4> get_ipv4() const;

        std::optional<ipv6_net> get_ipv6_net() const;

        std::optional<ipv6> get_ipv6() const;

        const ip_net& ip() const
        {
            return _ip;
        }

        const uint8_t& mask() const
        {
            return _mask;
        }

        uint8_t mask()
        {
            return _mask;
        }

        const oxen::quic::Address& address() const
        {
            return _addr;
        }

        oxen::quic::Address address()
        {
            return _addr;
        }

        bool operator<(const IPRange& other) const
        {
            return std::tie(_addr, _mask) < std::tie(other._addr, other._mask);
        }

        bool operator==(const IPRange& other) const
        {
            return std::tie(_addr, _mask) == std::tie(other._addr, other._mask);
        }
    };

    template <>
    inline constexpr bool IsToStringFormattable<IPRange> = true;
}  //  namespace llarp