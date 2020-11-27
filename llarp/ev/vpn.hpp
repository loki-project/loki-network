#pragma once

#include <net/ip_range.hpp>
#include <net/ip_packet.hpp>
#include <set>

namespace llarp
{
  struct Context;
}

namespace llarp::vpn
{
  struct InterfaceAddress
  {
    constexpr InterfaceAddress(IPRange r) : range{std::move(r)}
    {}
    IPRange range;
    int fam = AF_INET;
    bool
    operator<(const InterfaceAddress& other) const
    {
      return range < other.range or fam < other.fam;
    }
  };

  struct InterfaceInfo
  {
    std::string ifname;
    huint32_t dnsaddr;
    std::set<InterfaceAddress> addrs;
  };

  /// a vpn netwrok interface
  class NetworkInterface
  {
   public:
    NetworkInterface() = default;
    NetworkInterface(const NetworkInterface&) = delete;
    NetworkInterface(NetworkInterface&&) = delete;

    virtual ~NetworkInterface() = default;

    /// get pollable fd for reading
    virtual int
    PollFD() const = 0;

    /// human readable name for logging
    virtual std::string
    Name() const = 0;

    /// read next ip packet
    /// blocks until ready
    virtual net::IPPacket
    ReadNextPacket() = 0;

    /// return true if we have another packet to read
    virtual bool
    HasNextPacket() = 0;

    /// write a packet to the interface
    /// returns false if we dropped it
    virtual bool
    WritePacket(net::IPPacket pkt) = 0;
  };

  /// a vpn platform
  /// responsible for obtaining vpn interfaces
  class Platform
  {
   public:
    Platform() = default;
    Platform(const Platform&) = delete;
    Platform(Platform&&) = delete;
    virtual ~Platform() = default;

    /// get a new network interface fully configured given the interface info
    /// blocks until ready, throws on error
    virtual std::shared_ptr<NetworkInterface>
    ObtainInterface(InterfaceInfo info) = 0;
  };

  /// create native vpn platform
  std::unique_ptr<Platform>
  MakePlatform(llarp::Context* ctx);

}  // namespace llarp::vpn