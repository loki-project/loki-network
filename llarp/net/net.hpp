#pragma once

#include "uint128.hpp"
#include "address_info.hpp"
#include "ip_address.hpp"
#include "net_int.hpp"
#include "net.h"
#include "ip_range.hpp"
#include <llarp/util/mem.hpp>
#include <llarp/util/bits.hpp>

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

bool
operator==(const sockaddr& a, const sockaddr& b);

bool
operator==(const sockaddr_in& a, const sockaddr_in& b);

bool
operator==(const sockaddr_in6& a, const sockaddr_in6& b);

bool
operator<(const sockaddr_in6& a, const sockaddr_in6& b);

bool
operator<(const in6_addr& a, const in6_addr& b);

bool
operator==(const in6_addr& a, const in6_addr& b);

namespace llarp
{
  bool
  IsIPv4Bogon(const huint32_t& addr);

  bool
  IsBogon(const in6_addr& addr);

  bool
  IsBogon(const huint128_t addr);

  bool
  IsBogonRange(const in6_addr& host, const in6_addr& mask);

  bool
  AllInterfaces(int af, SockAddr& addr);

  /// get first network interface with public address
  bool
  GetBestNetIF(std::string& ifname, int af = AF_INET);

  /// look at adapter ranges and find a free one
  std::optional<IPRange>
  FindFreeRange();

  /// look at adapter names and find a free one
  std::optional<std::string>
  FindFreeTun();

  /// get network interface address for network interface with ifname
  std::optional<SockAddr>
  GetInterfaceAddr(const std::string& ifname, int af = AF_INET);

  /// get an interface's ip6 address
  std::optional<huint128_t>
  GetInterfaceIPv6Address(std::string ifname);

#ifdef _WIN32
  namespace net
  {
    std::optional<int>
    GetInterfaceIndex(huint32_t ip);
  }
#endif

}  // namespace llarp
