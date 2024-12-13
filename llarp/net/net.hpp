#pragma once

#include "uint128.hpp"
#include "address_info.hpp"
#include "ip_address.hpp"
#include "net_int.hpp"
#include "net.h"
#include "ip_range.hpp"
#include <llarp/util/mem.hpp>
#include <llarp/util/bits.hpp>

#include "interface_info.hpp"

#include <functional>
#include <cstdlib>  // for itoa
#include <vector>

// for addrinfo
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wspiapi.h>
#endif

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "bogon_ranges.hpp"

namespace llarp
{
  inline int
  cmp(const in_addr& a, const in_addr& b)
  {
    return memcmp(&a, &b, sizeof(in_addr));
  }

  inline int
  cmp(const in6_addr& a, const in6_addr& b)
  {
    return memcmp(&a, &b, sizeof(in6_addr));
  }

  namespace net
  {
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
      static const Platform*
      Default_ptr();

      virtual std::optional<SockAddr>
      AllInterfaces(SockAddr pubaddr) const = 0;

      inline SockAddr
      Wildcard(int af = AF_INET) const
      {
        if (af == AF_INET)
        {
          sockaddr_in addr{};
          addr.sin_family = AF_INET;
          addr.sin_addr.s_addr = htonl(INADDR_ANY);
          addr.sin_port = htons(0);
          return SockAddr{addr};
        }
        if (af == AF_INET6)
        {
          sockaddr_in6 addr6{};
          addr6.sin6_family = AF_INET6;
          addr6.sin6_port = htons(0);
          addr6.sin6_addr = IN6ADDR_ANY_INIT;
          return SockAddr{addr6};
        }
        throw std::invalid_argument{fmt::format("{} is not a valid address family", af)};
      }

      inline SockAddr
      WildcardWithPort(port_t port, int af = AF_INET) const
      {
        auto addr = Wildcard(af);
        addr.setPort(port);
        return addr;
      }

      virtual std::string
      LoopbackInterfaceName() const = 0;

      virtual bool
      HasInterfaceAddress(ipaddr_t ip) const = 0;

      /// return true if ip is considered a loopback address
      inline bool
      IsLoopbackAddress(ipaddr_t ip) const
      {
        return var::visit(
            [loopback6 = IPRange{huint128_t{uint128_t{0UL, 1UL}}, netmask_ipv6_bits(128)},
             loopback4 = IPRange::FromIPv4(127, 0, 0, 0, 8)](auto&& ip) {
              const auto h_ip = ToHost(ip);
              return loopback4.Contains(h_ip) or loopback6.Contains(h_ip);
            },
            ip);
      }

      /// return true if ip is considered a wildcard address
      inline bool
      IsWildcardAddress(ipaddr_t ip) const
      {
        return var::visit([](auto&& ip) { return not ip.n; }, ip);
      }

      virtual std::optional<std::string>
      GetBestNetIF(int af = AF_INET) const = 0;

      inline std::optional<SockAddr>
      MaybeInferPublicAddr(port_t default_port, int af = AF_INET) const
      {
        std::optional<SockAddr> maybe_addr;
        if (auto maybe_ifname = GetBestNetIF(af))
          maybe_addr = GetInterfaceAddr(*maybe_ifname, af);

        if (maybe_addr)
          maybe_addr->setPort(default_port);
        return maybe_addr;
      }

      virtual std::optional<IPRange>
      FindFreeRange() const = 0;

      virtual std::optional<std::string>
      FindFreeTun() const = 0;

      virtual std::optional<SockAddr>
      GetInterfaceAddr(std::string_view ifname, int af = AF_INET) const = 0;

      inline std::optional<huint128_t>
      GetInterfaceIPv6Address(std::string_view ifname) const
      {
        if (auto maybe_addr = GetInterfaceAddr(ifname, AF_INET6))
          return maybe_addr->asIPv6();
        return std::nullopt;
      }

      inline bool
      IsBogon(const SockAddr& addr) const
      {
        return IsBogonIP(addr.asIPv6());
      }

      inline bool
      IsBogonRange(const IPRange& range) const
      {
        // special case for 0.0.0.0/0
        if (range.IsV4() and range.netmask_bits == netmask_ipv6_bits(96))
          return false;
        // special case for ::/0
        if (IsWildcardAddress(ToNet(range.netmask_bits)))
          return false;
        return IsBogonIP(range.addr) or IsBogonIP(range.HighestAddr());
      }

      inline bool
      IsBogonIP(const net::ipaddr_t& addr) const
      {
        return IsBogonIP(var::visit(
            [](auto&& ip) {
              if constexpr (std::is_same_v<net::ipv4addr_t, std::decay_t<decltype(ip)>>)
                return ExpandV4(ToHost(ip));
              else
                return ToHost(ip);
            },
            addr));
      }
      inline bool
      IsBogonIP(const huint128_t& addr) const
      {
        if (not IPRange::V4MappedRange().Contains(addr))
        {
          for (const auto& v6_range : bogonRanges_v6)
          {
            if (v6_range.Contains(addr))
              return true;
          }
          return false;
        }
        const auto v4_addr = net::TruncateV6(addr);
        for (const auto& v4_range : bogonRanges_v4)
        {
          if (v4_range.Contains(v4_addr))
            return true;
        }
        return false;
      }

      virtual std::optional<int>
      GetInterfaceIndex(ipaddr_t ip) const = 0;

      /// returns a vector holding all of our network interfaces
      virtual std::vector<InterfaceInfo>
      AllNetworkInterfaces() const = 0;
    };

  }  // namespace net

}  // namespace llarp

inline bool
operator==(const in_addr& a, const in_addr& b)
{
  return llarp::cmp(a, b) == 0;
}

inline bool
operator==(const in6_addr& a, const in6_addr& b)
{
  return llarp::cmp(a, b) == 0;
}

inline bool
operator==(const sockaddr_in& a, const sockaddr_in& b)
{
  return a.sin_port == b.sin_port and a.sin_addr.s_addr == b.sin_addr.s_addr;
}

inline bool
operator==(const sockaddr_in6& a, const sockaddr_in6& b)
{
  return a.sin6_port == b.sin6_port and a.sin6_addr == b.sin6_addr;
}

inline bool
operator==(const sockaddr& a, const sockaddr& b)
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

inline bool
operator<(const in_addr& a, const in_addr& b)
{
  return llarp::cmp(a, b) < 0;
}

inline bool
operator<(const in6_addr& a, const in6_addr& b)
{
  return llarp::cmp(a, b) < 0;
}

inline bool
operator<(const sockaddr_in6& a, const sockaddr_in6& b)
{
  return std::tie(a.sin6_addr, a.sin6_port) < std::tie(b.sin6_addr, b.sin6_port);
}
