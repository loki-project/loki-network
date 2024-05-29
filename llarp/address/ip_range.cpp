#include "ip_range.hpp"

namespace llarp
{
    static auto logcat = log::Cat("iprange");

    void IPRange::_init_ip()
    {
        if (_is_ipv4)
        {
            _base_ip = _addr.to_ipv4().to_base(_mask);
            _ip_range = ipv4_range{std::get<ipv4>(_base_ip), _mask};
            _max_ip = std::get<ipv4_range>(_ip_range).max_ip();
        }
        else
        {
            _base_ip = _addr.to_ipv6().to_base(_mask);
            _ip_range = ipv6_range{std::get<ipv6>(_base_ip), _mask};
            _max_ip = std::get<ipv6_range>(_ip_range).max_ip();
        }
    }

    std::optional<IPRange> IPRange::from_string(std::string arg)
    {
        std::optional<IPRange> range = std::nullopt;
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
                    range = IPRange{std::move(_addr), std::move(_mask)};
                else
                    log::warning(logcat, "Failed to construct IPRange from string input:{}", arg);
            }
            catch (const std::exception& e)
            {
                log::error(logcat, "Exception caught parsing IPRange:{}", e.what());
            }
        }

        return range;
    }

    bool IPRange::contains(const IPRange& other) const
    {
        if (is_ipv4() ^ other.is_ipv4())
            return false;

        if (is_ipv4())
            return _contains(std::get<ipv4>(other.base_ip()));

        return _contains(std::get<ipv6>(other.base_ip()));
    }

    bool IPRange::_contains(const ipv4& other) const
    {
        return _ipv4_range().contains(other);
    }

    bool IPRange::_contains(const ipv6& other) const
    {
        return _ipv6_range().contains(other);
    }

    bool IPRange::contains(const ip_v& other) const
    {
        if (is_ipv4() ^ std::holds_alternative<ipv4>(other))
            return false;

        return is_ipv4() ? _contains(std::get<ipv4>(other)) : _contains(std::get<ipv6>(other));
    }

    std::optional<IPRange> IPRange::find_private_range(const std::list<IPRange>& excluding)
    {
        if (excluding.empty())
            return std::nullopt;

        auto filter = [&excluding](const ip_range_v& range) -> bool {
            for (const auto& e : excluding)
                if (e == range)
                    return false;
            return true;
        };

        using ip_type = decltype(excluding.front());

        // check ipv4 private addresses
        if constexpr (std::is_same_v<ip_type, ipv4_range>)
        {
            for (const auto& r : ipv4_private)
            {
                if (filter(r))
                    return r;
            }
        }
        else  // check ipv6 private addresses
        {
            for (size_t n = 0; n < num_ipv6_private; ++n)
            {
                if (auto v6 = ipv6(0xfd2e, 0x6c6f, 0x6b69, n) / 64; filter(v6))
                    return v6;
            }
        }

        return std::nullopt;
    }
}  //  namespace llarp
