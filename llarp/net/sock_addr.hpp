#pragma once

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <winsock2.h>

#include <ws2tcpip.h>
#include <wspiapi.h>
#endif

#include "net_int.hpp"

#include <llarp/util/formattable.hpp>

#include <oxenc/variant.h>

#include <string>
#include <string_view>

namespace llarp
{
    /// A simple SockAddr wrapper which provides a sockaddr_in (IPv4). Memory management is handled
    /// in constructor and destructor (if needed) and copying is disabled.
    struct SockAddr
    {
        SockAddr();
        // IPv4 constructors:
        SockAddr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, huint16_t port = {0});
        SockAddr(nuint32_t ip, nuint16_t port = {0});
        SockAddr(huint32_t ip, huint16_t port = {0});

        // IPv6 (or IPv4 if given a special IPv4-mapped IPv6 addr) in host order (including port).
        SockAddr(huint128_t ip, huint16_t port = {0});
        // IPv6 (or IPv4 if given a special IPv4-mapped IPv6 addr) in network order.  NB: port is
        // also in network order!
        SockAddr(nuint128_t ip, nuint16_t port = {0});

        // String ctors
        SockAddr(std::string_view addr);
        SockAddr(std::string_view addr, huint16_t port);  // port is in native (host) order

        SockAddr(const SockAddr&);
        SockAddr& operator=(const SockAddr&);

        SockAddr(const sockaddr& addr);
        SockAddr& operator=(const sockaddr& addr);

        SockAddr(const sockaddr_in& addr);
        SockAddr& operator=(const sockaddr_in& addr);

        SockAddr(const sockaddr_in6& addr);
        SockAddr& operator=(const sockaddr_in6& addr);

        SockAddr(const in6_addr& addr);
        SockAddr& operator=(const in6_addr& addr);

        explicit operator const sockaddr*() const;
        explicit operator const sockaddr_in*() const;
        explicit operator const sockaddr_in6*() const;

        size_t sockaddr_len() const;

        bool operator<(const SockAddr& other) const;

        bool operator==(const SockAddr& other) const;

        bool operator!=(const SockAddr& other) const
        {
            return not(*this == other);
        };

        void fromString(std::string_view str, bool allow_port = true);

        std::string to_string() const;

        /// convert ip address to string; ipv6_brackets - if true or omitted we add [...] around the
        /// IPv6 address, otherwise we return it bare.
        std::string hostString(bool ipv6_brackets = true) const;

        inline int Family() const
        {
            if (isIPv6())
                return AF_INET6;
            return AF_INET;
        }

        /// Returns true if this is an empty SockAddr, defined by having no IP address set. An empty
        /// IP address with a valid port is still considered empty.
        ///
        /// @return true if this is empty, false otherwise
        bool isEmpty() const;

        void setIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

        inline void setIP(std::variant<nuint32_t, nuint128_t> ip)
        {
            if (auto* v4 = std::get_if<nuint32_t>(&ip))
                setIPv4(*v4);
            if (auto* v6 = std::get_if<nuint128_t>(&ip))
                setIPv6(*v6);
        }

        void setIPv4(nuint32_t ip);

        void setIPv4(huint32_t ip);

        void setIPv6(huint128_t ip);

        void setIPv6(nuint128_t ip);

        void setPort(huint16_t port);

        void setPort(nuint16_t port);

        // Port is a native (host) value
        void setPort(uint16_t port)
        {
            setPort(huint16_t{port});
        }

        /// get the port of this sockaddr in network order
        net::port_t port() const;

        /// port is always returned in host order
        inline uint16_t getPort() const
        {
            return ToHost(port()).h;
        }

        /// True if this stores an IPv6 address, false if IPv4.
        bool isIPv6() const;

        /// !isIPv6()
        bool isIPv4() const;

        /// in network order
        nuint128_t getIPv6() const;
        nuint32_t getIPv4() const;

        std::variant<nuint32_t, nuint128_t> getIP() const;

        /// in host order
        huint128_t asIPv6() const;
        huint32_t asIPv4() const;

        const sockaddr_in* in()
        {
            return &addr4;
        }
        const sockaddr_in6* in6()
        {
            return &addr6;
        }

       private:
        bool m_empty = true;
        sockaddr_in6 addr6;
        sockaddr_in addr4;

        void init();

        void applyIPv4MapBytes();
    };

    template <>
    inline constexpr bool IsToStringFormattable<SockAddr> = true;

}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::SockAddr>
    {
        size_t operator()(const llarp::SockAddr& addr) const noexcept
        {
            const std::hash<uint16_t> port{};
            const std::hash<llarp::huint128_t> ip{};
            return (port(addr.getPort()) << 3) ^ ip(addr.asIPv6());
        }
    };
}  // namespace std
