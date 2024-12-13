#pragma once

#include "utils.hpp"

#include <llarp/util/concept.hpp>

#include <oxenc/bt_serialize.h>

namespace llarp
{
    inline constexpr size_t num_ipv6_private{65536};
    inline constexpr std::array ipv4_private = detail::generate_private_ipv4();

    struct IPRange
    {
      private:
        ip_net_v _ip_net;

        oxen::quic::Address _addr;
        uint8_t _mask;
        bool _is_ipv4;

        ip_v _base_ip;
        ip_v _max_ip;

        void _init_ip();

        // internal functions that do no type checking for ipv4 vs ipv6
        bool _contains(const ipv4& other) const;
        bool _contains(const ipv6& other) const;

        // getters to DRY out variant access
        ipv4_net& _ipv4_net() { return std::get<ipv4_net>(_ip_net); }
        const ipv4_net& _ipv4_net() const { return std::get<ipv4_net>(_ip_net); }
        ipv4_range _ipv4_range() const { return _ipv4_net().to_range(); }

        ipv6_net& _ipv6_net() { return std::get<ipv6_net>(_ip_net); }
        const ipv6_net& _ipv6_net() const { return std::get<ipv6_net>(_ip_net); }
        ipv6_range _ipv6_range() const { return _ipv6_net().to_range(); }

      public:
        IPRange() : IPRange{oxen::quic::Address{}, 0} {}

        explicit IPRange(std::string a, uint8_t m = 0) : IPRange{oxen::quic::Address{std::move(a), 0}, m} {}

        explicit IPRange(oxen::quic::Address a, uint8_t m) : _addr{std::move(a)}, _mask{m}, _is_ipv4{_addr.is_ipv4()}
        {
            _init_ip();
        }

        IPRange(const ipv4_net& ipv4)
            : _ip_net{ipv4},
              _addr{_ipv4_net().ip},
              _mask{_ipv4_net().mask},
              _is_ipv4{true},
              _base_ip{_ipv4_range().ip},
              _max_ip{_ipv4_net().max_ip()}
        {}

        IPRange(const ipv6_net& ipv6)
            : _ip_net{ipv6},
              _addr{ipv6.ip},
              _mask{ipv6.mask},
              _is_ipv4{false},
              _base_ip{ipv6.ip.to_base(_mask)},
              _max_ip{ipv6.max_ip()}
        {}

        static std::optional<IPRange> find_private_range(
            const std::list<IPRange>& excluding, bool ipv6_enabled = false);

        void bt_encode(oxenc::bt_list_producer& btlp) const { btlp.append(to_string()); }

        std::string to_string() const { return is_ipv4() ? _ipv4_net().to_string() : _ipv6_net().to_string(); }

        static std::optional<IPRange> from_string(std::string arg);

        bool contains(const IPRange& other) const;
        bool contains(const ip_v& other) const;
        bool contains(const ip_net_v& other) const;

        bool is_ipv4() const { return _is_ipv4; }

        ip_net_v get_ip_net() const { return _ip_net; }

        ip_v net_ip() const;

        ip_v base_ip() const { return _base_ip; }

        ip_v max_ip() const { return _max_ip; }

        const uint8_t& mask() const { return _mask; }
        uint8_t mask() { return _mask; }

        oxen::quic::Address base_address() const
        {
            return is_ipv4() ? oxen::quic::Address{_ipv4_range().ip} : oxen::quic::Address{_ipv6_range().ip};
        }

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

        bool operator==(const ip_net_v& other) const
        {
            if (_is_ipv4 and std::holds_alternative<ipv4_net>(other))
                return _ipv4_net() == std::get<ipv4_net>(other);
            if (not _is_ipv4 and std::holds_alternative<ipv6_net>(other))
                return _ipv6_net() == std::get<ipv6_net>(other);

            return false;
        }

        static constexpr bool to_string_formattable = true;
    };

    /** IPRangeIterator
        - When lokinet is assigning IP's within a range, this object functions as a robust managing context for the
            distribution and tracking of IP's within that range
    */
    struct IPRangeIterator
    {
      private:
        IPRange _ip_range;
        bool _is_ipv4;

        ip_v _current_ip;
        ip_v _max_ip;

        ipv4 _current_ipv4() { return std::get<ipv4>(_current_ip); }
        const ipv4& _current_ipv4() const { return std::get<ipv4>(_current_ip); }
        ipv6 _current_ipv6() { return std::get<ipv6>(_current_ip); }
        const ipv6& _current_ipv6() const { return std::get<ipv6>(_current_ip); }

        ipv4 _max_ipv4() { return std::get<ipv4>(_max_ip); }
        const ipv4& _max_ipv4() const { return std::get<ipv4>(_max_ip); }
        ipv6 _max_ipv6() { return std::get<ipv6>(_max_ip); }
        const ipv6& _max_ipv6() const { return std::get<ipv6>(_max_ip); }

        // internal incrementing mutators that will return true on success and false on overflow/reset
        bool _increment_ipv4()
        {
            bool ret = false;

            if (auto next_v4 = _current_ipv4().next_ip(); next_v4)
            {
                _current_ip = *next_v4;
                ret = true;
            }

            return ret;
        }

        bool _increment_ipv6()
        {
            bool ret = false;

            if (auto next_v6 = _current_ipv6().next_ip(); next_v6)
            {
                _current_ip = *next_v6;
                ret = true;
            }

            return ret;
        }

      public:
        IPRangeIterator() = default;

        IPRangeIterator(const IPRange& range)
            : _ip_range{range}, _is_ipv4{range.is_ipv4()}, _current_ip{range.net_ip()}, _max_ip{range.max_ip()}
        {}

        // Returns the next ip address in the iterating range; returns std::nullopt if range is exhausted
        std::optional<ip_v> next_ip()
        {
            std::optional<ip_v> ret = std::nullopt;

            if (range_exhausted())
                return ret;

            if (is_ipv4() ? _increment_ipv4() : _increment_ipv6())
                ret = _current_ip;

            return ret;
        }

        ip_v max_ip() { return _max_ip; }

        void reset()
        {
            _current_ip = _ip_range.base_ip();
            _max_ip = _ip_range.max_ip();
        }

        bool range_exhausted() const
        {
            return is_ipv4() ? _current_ipv4() == _max_ipv4() : _current_ipv6() == _max_ipv6();
        }

        bool is_ipv4() const { return _is_ipv4; }
    };

    namespace concepts
    {
        template <typename local_t>
        concept LocalAddrType = std::is_same_v<oxen::quic::Address, local_t> || std::is_same_v<IPRange, local_t>
            || std::is_same_v<ip_v, local_t>;
    }  // namespace concepts

}  //  namespace llarp

namespace std
{
    template <>
    struct hash<llarp::IPRange>
    {
        size_t operator()(const llarp::IPRange& r) const
        {
            size_t h;

            if (r.is_ipv4())
                h = hash<llarp::ipv4>{}(std::get<llarp::ipv4>(r.base_ip()));
            else
                h = hash<llarp::ipv6>{}(std::get<llarp::ipv6>(r.base_ip()));

            h ^= hash<uint8_t>{}(r.mask()) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);

            return h;
        }
    };

}  //  namespace std
