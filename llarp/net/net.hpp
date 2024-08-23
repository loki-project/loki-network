#pragma once

#include "interface_info.hpp"
#include "net.h"
#include "net_int.hpp"
#include "uint128.hpp"

#include <llarp/address/ip_range.hpp>
#include <llarp/util/mem.hpp>

#include <oxen/quic/address.hpp>

#include <cstdlib>  // for itoa
#include <functional>
#include <vector>

// for addrinfo
#ifndef _WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#else
#include <winsock2.h>

#include <ws2tcpip.h>
#include <wspiapi.h>
#endif

#ifndef _WIN32
#include <arpa/inet.h>
#endif

namespace llarp
{
    inline int cmp(const in_addr& a, const in_addr& b)
    {
        return memcmp(&a, &b, sizeof(in_addr));
    }

    inline int cmp(const in6_addr& a, const in6_addr& b)
    {
        return memcmp(&a, &b, sizeof(in6_addr));
    }

    namespace net
    {
        struct if_info
        {
            explicit if_info(int _af = AF_INET) : af{_af} {}

            int af{};
            std::optional<std::string> if_name = std::nullopt;
            std::optional<oxen::quic::Address> if_addr = std::nullopt;
            std::optional<oxen::quic::Address> if_netmask = std::nullopt;
            std::optional<int> if_index = std::nullopt;

            operator bool() const { return if_name and if_addr /* and if_netmask */ and if_index; }
        };

        /// network platform (all methods virtual so it can be mocked by unit tests)
        class Platform
        {
          public:
            Platform() = default;
            virtual ~Platform() = default;
            Platform(const Platform&) = delete;
            Platform(Platform&&) = delete;

            /// get a pointer to our signleton instance used by main lokinet
            /// unit test mocks will not call this
            static const Platform* Default_ptr();

            virtual std::optional<oxen::quic::Address> all_interfaces(oxen::quic::Address pubaddr) const = 0;

            inline oxen::quic::Address wildcard(int af = AF_INET) const
            {
                oxen::quic::Address ret{};

                if (af == AF_INET)
                {
                    in_addr add{INADDR_ANY};
                    ret.set_addr(&add);
                }
                if (af == AF_INET6)
                {
                    ret.set_addr(&in6addr_any);
                }
                throw std::invalid_argument{"{} is not a valid address family"_format(af)};
            }

            inline oxen::quic::Address wildcard_with_port(uint16_t port, int af = AF_INET) const
            {
                auto addr = wildcard(af);
                addr.set_port(port);
                return addr;
            }

            virtual std::string loopback_interface_name() const = 0;

            virtual bool has_interface_address(ip_v ip) const = 0;

            // Attempts to guess a good default public network address from the system's public IP
            // addresses; the returned Address (if set) will have its port set to the given value.
            virtual std::optional<oxen::quic::Address> get_best_public_address(bool ipv4, uint16_t port) const = 0;

            virtual std::optional<IPRange> find_free_range(bool ipv6_enabled = false) const = 0;

            virtual std::optional<std::string> find_free_tun(int af = AF_INET) const = 0;

            virtual if_info find_free_interface(int af = AF_INET) const = 0;

            virtual std::optional<oxen::quic::Address> get_interface_addr(
                std::string_view ifname, int af = AF_INET) const = 0;

            inline std::optional<oxen::quic::Address> get_interface_ipv6_addr(std::string_view ifname) const
            {
                return get_interface_addr(ifname, AF_INET6);
            }

            virtual std::optional<int> get_interface_index(ip_v ip) const = 0;

            /// returns a vector holding all of our network interfaces
            virtual std::vector<InterfaceInfo> all_network_interfaces() const = 0;
        };

    }  // namespace net

}  // namespace llarp

inline bool operator==(const in_addr& a, const in_addr& b)
{
    return llarp::cmp(a, b) == 0;
}

inline bool operator==(const in6_addr& a, const in6_addr& b)
{
    return llarp::cmp(a, b) == 0;
}

inline bool operator==(const sockaddr_in& a, const sockaddr_in& b)
{
    return a.sin_port == b.sin_port and a.sin_addr.s_addr == b.sin_addr.s_addr;
}

inline bool operator==(const sockaddr_in6& a, const sockaddr_in6& b)
{
    return a.sin6_port == b.sin6_port and a.sin6_addr == b.sin6_addr;
}

inline bool operator==(const sockaddr& a, const sockaddr& b)
{
    if (a.sa_family != b.sa_family)
        return false;
    switch (a.sa_family)
    {
        case AF_INET:
            return reinterpret_cast<const sockaddr_in&>(a) == reinterpret_cast<const sockaddr_in&>(b);
        case AF_INET6:
            return reinterpret_cast<const sockaddr_in6&>(a) == reinterpret_cast<const sockaddr_in6&>(b);
        default:
            return false;
    }
}

inline bool operator<(const in_addr& a, const in_addr& b)
{
    return llarp::cmp(a, b) < 0;
}

inline bool operator<(const in6_addr& a, const in6_addr& b)
{
    return llarp::cmp(a, b) < 0;
}

inline bool operator<(const sockaddr_in6& a, const sockaddr_in6& b)
{
    return std::tie(a.sin6_addr, a.sin6_port) < std::tie(b.sin6_addr, b.sin6_port);
}
