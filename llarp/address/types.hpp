#pragma once

#include <llarp/util/formattable.hpp>

#include <oxen/quic.hpp>

namespace llarp
{
    using ipv4 = oxen::quic::ipv4;
    using ipv6 = oxen::quic::ipv6;
    using ip_v = std::variant<ipv4, ipv6>;
    using ipv4_range = oxen::quic::ipv4_range;
    using ipv6_range = oxen::quic::ipv6_range;
    using ipv4_net = oxen::quic::ipv4_net;
    using ipv6_net = oxen::quic::ipv6_net;
    using ip_net_v = std::variant<ipv4_net, ipv6_net>;

    namespace concepts
    {
        template <typename ip_t>
        concept IPType = std::is_same_v<ip_t, ipv4> || std::is_same_v<ip_t, ipv6>;

        template <typename ip_range_t>
        concept IPRangeType = std::is_same_v<ip_range_t, ipv4_net> || std::is_same_v<ip_range_t, ipv6_net>;
    }  // namespace concepts

    using KeyedAddress = oxen::quic::RemoteAddress;
}  //   namespace llarp

namespace std
{
    template <>
    struct hash<llarp::ipv4>
    {
        size_t operator()(const llarp::ipv4& obj) const { return hash<decltype(obj.addr)>{}(obj.addr); }
    };

    template <>
    struct hash<llarp::ipv6>
    {
        size_t operator()(const llarp::ipv6& obj) const
        {
            auto h = hash<decltype(obj.hi)>{}(obj.hi);
            h ^= hash<decltype(obj.lo)>{}(obj.lo) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };

    template <>
    struct hash<llarp::ip_v>
    {
        size_t operator()(const llarp::ip_v& obj) const
        {
            if (auto maybe_v4 = std::get_if<llarp::ipv4>(&obj))
                return hash<llarp::ipv4>{}(*maybe_v4);

            return hash<llarp::ipv6>{}(std::get<llarp::ipv6>(obj));
        }
    };
}  //  namespace std
