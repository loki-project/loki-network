#pragma once

#include "utils.hpp"

#include <llarp/util/concept.hpp>

#include <oxenc/bt_serialize.h>

namespace llarp
{
    // inline constexpr std::array ipv4_private = {};

    template <IPRangeType ip_range_t>
    struct IP_Range
    {
        using ipv_t = std::conditional<std::is_same_v<ip_range_t, ipv4_range>, ipv4, ipv6>;

      private:
        oxen::quic::Address _addr;
        uint8_t _mask;

        bool _is_ipv4;

        ipv_t _base_ip;
        ip_range_t _ip_range;
        ipv_t _max_ip;

        void _init_ip()
        {
            if (_is_ipv4)
            {
                _base_ip = _addr.to_ipv4();
                _ip_range = ipv4_range{_base_ip, _mask};
            }
            else
            {
                _base_ip = _addr.to_ipv6();
                _ip_range = ipv6_range{_base_ip, _mask};
            }

            _max_ip = _ip_range.max_ip();
        }

        // does not check if both are ipv{4,6}; called by public methods
        constexpr bool _contains(const ipv_t& other) { return _ip_range.contains(other); }

      public:
        IP_Range() : IP_Range("", 0) {}

        explicit IP_Range(std::string a, uint8_t m) : IP_Range{oxen::quic::Address{std::move(a), 0}, m} {}

        explicit IP_Range(oxen::quic::Address a, uint8_t m) : _addr{std::move(a)}, _mask{m}, _is_ipv4{_addr.is_ipv4()}
        {
            _init_ip();
        }

        static std::optional<IP_Range<ip_range_t>> from_string(std::string arg)
        {
            std::optional<IP_Range<ip_range_t>> range = std::nullopt;
            oxen::quic::Address _addr;
            uint8_t _mask;

            if (auto pos = arg.find_first_of('/'); pos != std::string::npos)
            {
                try
                {
                    auto [host, p] = detail::parse_addr(arg.substr(0, pos), 0);
                    assert(p == 0);
                    _addr = oxen::quic::Address{host, p};

                    if (parse_int(arg.substr(pos), _mask))
                        range = IP_Range{std::move(_addr), std::move(_mask)};
                    else
                        throw std::invalid_argument{"Failed to construct IPRange from string input:{}"_format(arg)};
                }
                catch (...)
                {
                    throw;
                }
            }

            return range;
        }

        static std::optional<IP_Range<ip_range_t>> find_private_range(const std::list<IP_Range<ip_range_t>>& excluding)
        {
            auto filter = [&excluding](const IP_Range<ip_range_t>& range) -> bool {
                for (const auto& e : excluding)
                    if (e == range)
                        return false;
                return true;
            };

            (void)filter;

            return std::nullopt;
        }

        const std::string to_string() const { return _ip_range.to_string(); }

        constexpr bool contains(const IP_Range<ip_range_t>& other) const
        {
            // IPRanges should be the same IP address type
            if constexpr (is_ipv4() ^ other.is_ipv4())
                return false;

            return _contains(other.get_base_ip());
        }

        constexpr bool contains(const ipv_t& other) const
        {
            // TODO: check if this is superfluous; ipv_t "should" be the same?
            if constexpr (not std::is_same_v<decltype(_base_ip), decltype(other)>)
                return false;

            return _contains(other);
        }

        constexpr bool is_ipv4() const { return _is_ipv4; }

        decltype(_ip_range) get_ip_range() const { return _ip_range; }

        decltype(_base_ip) get_base_ip() const { return _base_ip; }

        decltype(_max_ip) get_max_ip() const { return _max_ip; }

        const uint8_t& mask() const { return _mask; }
        uint8_t mask() { return _mask; }

        const oxen::quic::Address& address() const { return _addr; }
        oxen::quic::Address address() { return _addr; }

        constexpr bool operator==(const IP_Range<ip_range_t>& other)
        {
            return std::tie(_addr, _ip_range) == std::tie(other._addr, other._ip_range);
        }
    };

    struct IPRange
    {
      private:
        oxen::quic::Address _addr;
        uint8_t _mask;

        bool _is_ipv4;

        std::optional<ipv4_range> _ipv4_range;

        std::optional<ipv6_range> _ipv6_range;

        ip_range_v _ip;

        oxen::quic::Address _max_addr;

        ip_range_v init_ip();

        oxen::quic::Address init_max();

      public:
        IPRange() : IPRange{"", 0} {}

        explicit IPRange(std::string a, uint8_t m = 0)
            : _addr{std::move(a), 0}, _mask{m}, _is_ipv4{_addr.is_ipv4()}, _ip{init_ip()}
        {}

        explicit IPRange(oxen::quic::Address a, uint8_t m)
            : _addr{a}, _mask{m}, _is_ipv4{_addr.is_ipv4()}, _ip{init_ip()}
        {}

        // TODO: finish this
        static std::optional<IPRange> find_private_range(const std::list<IPRange>& excluding);

        void bt_encode(oxenc::bt_list_producer& btlp) const { btlp.append(to_string()); }

        std::string to_string() const { return _addr.to_string() + "/" + std::to_string(_mask); }

        static std::optional<IPRange> from_string(std::string arg);

        bool contains(const IPRange& other) const;

        bool contains(const ipv4& other) const;

        bool contains(const ipv6& other) const;

        bool contains(const ip_v& other) const;

        bool is_ipv4() const { return _is_ipv4; }

        std::optional<ipv4_range> get_ipv4_net() const;

        std::optional<ipv4> get_ipv4() const;

        std::optional<ipv6_range> get_ipv6_net() const;

        std::optional<ipv6> get_ipv6() const;

        std::optional<ip_v> get_ip();

        const uint8_t& mask() const { return _mask; }

        uint8_t mask() { return _mask; }

        const oxen::quic::Address& address() const { return _addr; }

        oxen::quic::Address address() { return _addr; }

        bool operator<(const IPRange& other) const
        {
            return std::tie(_addr, _mask) < std::tie(other._addr, other._mask);
        }

        bool operator==(const IPRange& other) const
        {
            return std::tie(_addr, _mask) == std::tie(other._addr, other._mask);
        }
    };

    template <typename local_t>
    concept LocalAddrType = std::is_same_v<oxen::quic::Address, local_t> || std::is_same_v<IPRange, local_t>;
}  //  namespace llarp

namespace std
{
    inline constexpr size_t golden_ratio_inverse = sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;

    template <>
    struct hash<llarp::IPRange>
    {
        size_t operator()(const llarp::IPRange& r) const
        {
            auto& addr = r.address();
            auto& m = r.mask();

            if (r.is_ipv4())
                return hash<llarp::ipv4>{}(addr.to_ipv4().to_base(m));
            return hash<llarp::ipv6>{}(addr.to_ipv6().to_base(m));
        }
    };

    template <llarp::IPRangeType ip_range_t>
    struct hash<llarp::IP_Range<ip_range_t>>
    {
        size_t operator()(const llarp::IP_Range<ip_range_t>& r) const
        {
            auto h = hash<decltype(r.get_base_ip())>{}(r.get_base_ip());
            h ^= hash<decltype(r.mask())>{}(r.mask());
            return h;
        }
    };
}  //  namespace std
