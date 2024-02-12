#pragma once

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
