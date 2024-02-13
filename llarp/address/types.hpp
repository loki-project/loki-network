#pragma once

#include <llarp/util/formattable.hpp>

#include <oxen/quic.hpp>

namespace llarp
{
    using ipv4 = oxen::quic::ipv4;
    using ipv6 = oxen::quic::ipv6;
    using ip = std::variant<ipv4, ipv6>;
    using ipv4_net = oxen::quic::ipv4_net;
    using ipv6_net = oxen::quic::ipv6_net;
    using ip_net = std::variant<ipv4_net, ipv6_net>;
}  //   namespace llarp

namespace std
{
    template <>
    struct hash<llarp::ipv4>
    {
        size_t operator()(const llarp::ipv4& obj) const
        {
            return hash<decltype(obj.addr)>{}(obj.addr);
        }
    };

    template <>
    struct hash<llarp::ipv6>
    {
        size_t operator()(const llarp::ipv6& obj) const
        {
            auto h = hash<decltype(obj.hi)>{}(obj.hi);
            h ^= hash<decltype(obj.lo)>{}(obj.lo);
            return h;
        }
    };

    template <>
    struct hash<llarp::ip>
    {
        size_t operator()(const llarp::ip& obj) const
        {
            if (auto maybe_v4 = std::get_if<llarp::ipv4>(&obj))
                return hash<llarp::ipv4>{}(*maybe_v4);

            auto maybe_v6 = std::get_if<llarp::ipv6>(&obj);
            return hash<llarp::ipv6>{}(*maybe_v6);
        }
    };
}  //  namespace std
