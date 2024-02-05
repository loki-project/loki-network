#pragma once

// for addrinfo
#ifndef _WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#else
#include <winsock2.h>

#include <ws2tcpip.h>

#define inet_aton(x, y) inet_pton(AF_INET, x, y)
#endif

#include "net.h"
#include "uint128.hpp"

#include <llarp/util/formattable.hpp>

#include <oxenc/variant.h>

#include <cstdlib>  // for itoa
#include <iostream>
#include <vector>

namespace llarp
{
    template <typename UInt_t>
    struct huint_t
    {
        UInt_t h;

        constexpr huint_t operator&(huint_t x) const
        {
            return huint_t{UInt_t{h & x.h}};
        }

        constexpr huint_t operator|(huint_t x) const
        {
            return huint_t{UInt_t{h | x.h}};
        }

        constexpr huint_t operator-(huint_t x) const
        {
            return huint_t{UInt_t{h - x.h}};
        }

        constexpr huint_t operator+(huint_t x) const
        {
            return huint_t{UInt_t{h + x.h}};
        }

        constexpr huint_t operator^(huint_t x) const
        {
            return huint_t{UInt_t{h ^ x.h}};
        }

        constexpr huint_t operator~() const
        {
            return huint_t{UInt_t{~h}};
        }

        constexpr huint_t operator<<(int n) const
        {
            UInt_t v{h};
            v <<= n;
            return huint_t{v};
        }

        inline huint_t operator++()
        {
            ++h;
            return *this;
        }

        inline huint_t operator--()
        {
            --h;
            return *this;
        }

        constexpr bool operator<(huint_t x) const
        {
            return h < x.h;
        }

        constexpr bool operator!=(huint_t x) const
        {
            return h != x.h;
        }

        constexpr bool operator==(huint_t x) const
        {
            return h == x.h;
        }

        using V6Container = std::vector<uint8_t>;
        [[deprecated]] void ToV6(V6Container& c);

        std::string to_string() const;

        bool FromString(const std::string&);
    };

    using huint32_t = huint_t<uint32_t>;
    using huint16_t = huint_t<uint16_t>;
    using huint128_t = huint_t<llarp::uint128_t>;

    template <typename UInt_t>
    struct nuint_t
    {
        UInt_t n = 0;

        constexpr nuint_t operator&(nuint_t x) const
        {
            return nuint_t{UInt_t(n & x.n)};
        }

        constexpr nuint_t operator|(nuint_t x) const
        {
            return nuint_t{UInt_t(n | x.n)};
        }

        constexpr nuint_t operator^(nuint_t x) const
        {
            return nuint_t{UInt_t(n ^ x.n)};
        }

        constexpr nuint_t operator~() const
        {
            return nuint_t{UInt_t(~n)};
        }

        inline nuint_t operator++()
        {
            ++n;
            return *this;
        }
        inline nuint_t operator--()
        {
            --n;
            return *this;
        }

        constexpr bool operator<(nuint_t x) const
        {
            return n < x.n;
        }

        constexpr bool operator!=(nuint_t x) const
        {
            return n != x.n;
        }

        constexpr bool operator==(nuint_t x) const
        {
            return n == x.n;
        }

        using V6Container = std::vector<uint8_t>;
        [[deprecated]] void ToV6(V6Container& c);

        std::string to_string() const;

        bool FromString(const std::string& data)
        {
            huint_t<UInt_t> x;
            if (not x.FromString(data))
                return false;
            *this = ToNet(x);
            return true;
        }

        inline static nuint_t<UInt_t> from_string(const std::string& str)
        {
            nuint_t<UInt_t> x{};
            if (not x.FromString(str))
                throw std::invalid_argument{fmt::format("{} is not a valid value")};
            return x;
        }

        template <typename... Args_t>
        inline static nuint_t<UInt_t> from_host(Args_t&&... args)
        {
            return ToNet(huint_t<UInt_t>{std::forward<Args_t>(args)...});
        }
    };

    namespace net
    {
        /// hides the nuint types used with net_port_t / net_ipv4addr_t / net_ipv6addr_t
        namespace
        {
            using n_uint16_t = llarp::nuint_t<uint16_t>;
            using n_uint32_t = llarp::nuint_t<uint32_t>;
            using n_uint128_t = llarp::nuint_t<llarp::uint128_t>;
        }  // namespace

        using port_t = n_uint16_t;
        using ipv4addr_t = n_uint32_t;
        using flowlabel_t = n_uint32_t;
        using ipv6addr_t = n_uint128_t;
        using ipaddr_t = std::variant<ipv4addr_t, ipv6addr_t>;

        std::string to_string(const ipaddr_t& ip);

        huint16_t ToHost(port_t);
        huint32_t ToHost(ipv4addr_t);
        huint128_t ToHost(ipv6addr_t);

        port_t ToNet(huint16_t);
        ipv4addr_t ToNet(huint32_t);
        ipv6addr_t ToNet(huint128_t);

    }  // namespace net

    template <>
    inline constexpr bool IsToStringFormattable<huint128_t> = true;
    template <>
    inline constexpr bool IsToStringFormattable<huint32_t> = true;
    template <>
    inline constexpr bool IsToStringFormattable<huint16_t> = true;
    template <>
    inline constexpr bool IsToStringFormattable<net::ipv6addr_t> = true;
    template <>
    inline constexpr bool IsToStringFormattable<net::ipv4addr_t> = true;
    template <>
    inline constexpr bool IsToStringFormattable<net::port_t> = true;

    using nuint16_t /* [[deprecated("use llarp::net::port_t instead")]] */ = llarp::net::port_t;
    using nuint32_t /* [[deprecated("use llarp::net::ipv4addr_t instead")]] */ = llarp::net::ipv4addr_t;
    using nuint128_t /* [[deprecated("use llarp::net::ipv6addr_t instead")]] */ = llarp::net::ipv6addr_t;

    template <typename UInt_t>
    /*   [[deprecated("use llarp::net::ToNet instead")]] */ inline llarp::nuint_t<UInt_t> ToNet(
        llarp::huint_t<UInt_t> x)
    {
        return llarp::net::ToNet(x);
    }

    template <typename UInt_t>
    /*   [[deprecated("use llarp::net::ToHost instead")]] */ inline llarp::huint_t<UInt_t> ToHost(
        llarp::nuint_t<UInt_t> x)
    {
        return llarp::net::ToHost(x);
    }

    /*   [[deprecated("use llarp::net::ToHost instead")]] */ inline net::ipv4addr_t xhtonl(huint32_t x)
    {
        return ToNet(x);
    }
}  // namespace llarp

namespace std
{
    template <typename UInt_t>
    struct hash<llarp::nuint_t<UInt_t>>
    {
        size_t operator()(const llarp::nuint_t<UInt_t>& x) const
        {
            return std::hash<UInt_t>{}(x.n);
        }
    };

    template <typename UInt_t>
    struct hash<llarp::huint_t<UInt_t>>
    {
        size_t operator()(const llarp::huint_t<UInt_t>& x) const
        {
            return std::hash<UInt_t>{}(x.h);
        }
    };
}  // namespace std
