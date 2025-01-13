#include "ip_range.hpp"

namespace llarp
{
    static auto logcat = log::Cat("iprange");

    void IPRange::_init_ip()
    {
        if (_is_ipv4)
        {
            _ip_net = _addr.to_ipv4() % _mask;
            _base_ip = _ipv4_range().ip;
            _max_ip = _ipv4_net().max_ip();
        }
        else
        {
            _ip_net = _addr.to_ipv6() % _mask;
            _base_ip = _ipv6_range().ip;
            _max_ip = _ipv6_net().max_ip();
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

                if (parse_int(arg.substr(pos + 1), _mask))
                    range = IPRange{std::move(_addr), _mask};
                else
                    log::warning(
                        logcat,
                        "Failed to construct IPRange from string input:{} parsed into addr:{}, mask:{}",
                        arg,
                        _addr,
                        arg.substr(pos + 1));
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

    bool IPRange::_contains(const ipv4& other) const { return _ipv4_range().contains(other); }

    bool IPRange::_contains(const ipv6& other) const { return _ipv6_range().contains(other); }

    bool IPRange::contains(const ip_v& other) const
    {
        if (is_ipv4() ^ std::holds_alternative<ipv4>(other))
            return false;

        return is_ipv4() ? _contains(std::get<ipv4>(other)) : _contains(std::get<ipv6>(other));
    }

    bool IPRange::contains(const ip_net_v& other) const
    {
        if (is_ipv4() ^ std::holds_alternative<ipv4_net>(other))
            return false;

        return is_ipv4() ? _contains(std::get<ipv4_net>(other).to_range().ip)
                         : _contains(std::get<ipv6_net>(other).to_range().ip);
    }

    ip_v IPRange::net_ip() const
    {
        if (is_ipv4())
            return _ipv4_net().ip;
        return _ipv6_net().ip;
    }

    std::optional<IPRange> IPRange::find_private_range(const std::list<IPRange>& excluding, bool ipv6_enabled)
    {
        if (excluding.empty())
            return std::nullopt;

        auto filter = [&excluding](const ip_net_v& range) -> bool {
            for (const auto& e : excluding)
            {
                if (e.contains(range))
                    return false;
            }
            log::trace(logcat, "{}", std::get<ipv4_net>(range).ip);
            return true;
        };

        // check ipv4 private addresses
        if (excluding.front().is_ipv4())
        {
            for (const auto& r : ipv4_private)
            {
                if (filter(r))
                    return r;
            }
        }
        // the invoking context also ensures thet the list `excluding` also does not include ipv6 before passing
        // the boolean to this function
        else if (ipv6_enabled)
        {
            for (size_t n = 0; n < num_ipv6_private; ++n)
            {
                if (auto v6 = ipv6(0xfd2e, 0x6c6f, 0x6b69, n, 0x0000, 0x0000, 0x0000, 0x0001) % 64; filter(v6))
                    return v6;
            }
        }

        return std::nullopt;
    }
}  //  namespace llarp
