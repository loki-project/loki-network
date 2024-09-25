#ifdef WITH_SYSTEMD
#include "sd_platform.hpp"

extern "C"
{
#include <net/if.h>
}

#include <llarp/linux/dbus.hpp>

namespace llarp::dns::sd
{
    void Platform::set_resolver(unsigned int if_ndx, oxen::quic::Address dns, bool global)
    {
        linux::DBUS _dbus{"org.freedesktop.resolve1", "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager"};
        // This passing address by bytes and using two separate calls for ipv4/ipv6 is gross, but
        // the alternative is to build up a bunch of crap with va_args, which is slightly more
        // gross.
        const bool isStandardDNSPort = dns.port() == 53;
        if (dns.is_ipv6())
        {
            ipv6 ipv6{&dns.in6().sin6_addr};
            static_assert(sizeof(ipv6) == 16);

            auto* a = reinterpret_cast<const uint8_t*>(&ipv6);
            if (isStandardDNSPort)
            {
                _dbus(
                    "SetLinkDNS",
                    "ia(iay)",
                    (int32_t)if_ndx,
                    (int)1,             // number of "iayqs"s we are passing
                    (int32_t)AF_INET6,  // network address type
                    (int)16,            // network addr byte size
                                        // clang-format off
              a[0], a[1], a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
              a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15] // yuck
                                        // clang-format on
                );
            }
            else
            {
                _dbus(
                    "SetLinkDNSEx",
                    "ia(iayqs)",
                    (int32_t)if_ndx,
                    (int)1,             // number of "iayqs"s we are passing
                    (int32_t)AF_INET6,  // network address type
                    (int)16,            // network addr byte size
                    // clang-format off
              a[0], a[1], a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
              a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], // yuck
                            // clang-format on
                    dns.port(),
                    nullptr  // dns server name (for TLS SNI which we don't care about)
                );
            }
        }
        else
        {
            ipv4 ipv4{oxenc::big_to_host<uint32_t>(dns.in4().sin_addr.s_addr)};

            auto* a = reinterpret_cast<const uint8_t*>(&ipv4);

            if (isStandardDNSPort)
            {
                _dbus(
                    "SetLinkDNS",
                    "ia(iay)",
                    (int32_t)if_ndx,
                    (int)1,            // number of "iayqs"s we are passing
                    (int32_t)AF_INET,  // network address type
                    (int)4,            // network addr byte size
                                       // clang-format off
              a[0], a[1], a[2], a[3] // yuck
                                       // clang-format on
                );
            }
            else
            {
                _dbus(
                    "SetLinkDNSEx",
                    "ia(iayqs)",
                    (int32_t)if_ndx,
                    (int)1,            // number of "iayqs"s we are passing
                    (int32_t)AF_INET,  // network address type
                    (int)4,            // network addr byte size
                    // clang-format off
              a[0], a[1], a[2], a[3], // yuck
                           // clang-format on
                    dns.port(),
                    nullptr  // dns server name (for TLS SNI which we don't care about)
                );
            }
        }

        if (global)
            // Setting "." as a routing domain gives this DNS server higher priority in resolution
            // compared to dns servers that are set without a domain (e.g. the default for a
            // DHCP-configured DNS server)
            _dbus(
                "SetLinkDomains",
                "ia(sb)",
                (int32_t)if_ndx,
                (int)1,  // array size
                "."      // global DNS root
            );
        else
            // Only resolve .loki and .snode through lokinet (so you keep using your local DNS
            // server for everything else, which is nicer than forcing everything though lokinet's
            // upstream DNS).
            _dbus(
                "SetLinkDomains",
                "ia(sb)",
                (int32_t)if_ndx,
                (int)2,   // array size
                "loki",   // domain
                (int)1,   // routing domain = true
                "snode",  // domain
                (int)1    // routing domain = true
            );
    }
}  // namespace llarp::dns::sd
#endif
