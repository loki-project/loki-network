#pragma once

#include "i_packet_io.hpp"

#include <llarp/address/ip_packet.hpp>
#include <llarp/address/ip_range.hpp>
#include <llarp/net/net.hpp>

#include <oxen/quic.hpp>
#include <oxenc/variant.h>

#include <set>

namespace llarp
{
    struct Context;
    struct Router;
}  // namespace llarp

namespace llarp::vpn
{
    struct InterfaceAddress
    {
        InterfaceAddress(IPRange r) : range{std::move(r)}, fam{range.is_ipv4() ? AF_INET : AF_INET6} {}

        IPRange range;
        int fam;

        bool operator<(const InterfaceAddress& other) const
        {
            return std::tie(range, fam) < std::tie(other.range, other.fam);
        }
    };

    struct InterfaceInfo
    {
        std::string ifname;
        unsigned int index;
        std::vector<InterfaceAddress> addrs;

        inline IPRange operator[](size_t idx) const { return addrs[idx].range; }
    };

    /// a vpn network interface
    class NetworkInterface : public I_Packet_IO
    {
      protected:
        InterfaceInfo _info;

      public:
        NetworkInterface(InterfaceInfo info) : _info{std::move(info)} {}
        NetworkInterface(const NetworkInterface&) = delete;
        NetworkInterface(NetworkInterface&&) = delete;

        const InterfaceInfo& interface_info() const { return _info; }

        /// idempotently wake up the upper layers as needed (platform dependant)
        virtual void MaybeWakeUpperLayers() const {};
    };

    class AbstractRouteManager
    {
      public:
        AbstractRouteManager() = default;
        AbstractRouteManager(const AbstractRouteManager&) = delete;
        AbstractRouteManager(AbstractRouteManager&&) = delete;
        virtual ~AbstractRouteManager() = default;

        virtual const llarp::net::Platform* net_ptr() const;

        inline const llarp::net::Platform& Net() const { return *net_ptr(); }

        virtual void add_route(oxen::quic::Address ip, oxen::quic::Address gateway) = 0;

        virtual void delete_route(oxen::quic::Address ip, oxen::quic::Address gateway) = 0;

        virtual void add_default_route_via_interface(NetworkInterface& vpn) = 0;

        virtual void delete_default_route_via_interface(NetworkInterface& vpn) = 0;

        virtual void add_route_via_interface(NetworkInterface& vpn, IPRange range) = 0;

        virtual void delete_route_via_interface(NetworkInterface& vpn, IPRange range) = 0;

        virtual std::vector<oxen::quic::Address> get_non_interface_gateways(NetworkInterface& vpn) = 0;

        virtual void add_blackhole(){};

        virtual void delete_blackhole(){};
    };

    /// a vpn platform
    /// responsible for obtaining vpn interfaces
    class Platform
    {
      protected:
        /// get a new network interface fully configured given the interface info
        /// blocks until ready, throws on error
        virtual std::shared_ptr<NetworkInterface> ObtainInterface(InterfaceInfo info, Router* router) = 0;

      public:
        Platform() = default;
        Platform(const Platform&) = delete;
        Platform(Platform&&) = delete;
        virtual ~Platform() = default;

        /// create and start a network interface
        std::shared_ptr<NetworkInterface> CreateInterface(InterfaceInfo info, Router* router)
        {
            if (auto netif = ObtainInterface(std::move(info), router))
            {
                netif->Start();
                return netif;
            }
            return nullptr;
        }

        /// get owned ip route manager for managing routing table
        virtual AbstractRouteManager& RouteManager() = 0;

        /// create a packet io that will read (and optionally write) packets on a network interface
        /// the lokinet process does not own
        /// @param index the interface index of the network interface to use or 0 for all
        /// interfaces on the system
        virtual std::shared_ptr<I_Packet_IO> create_packet_io(
            [[maybe_unused]] unsigned int ifindex,
            [[maybe_unused]] const std::optional<oxen::quic::Address>& dns_upstream_src)
        {
            throw std::runtime_error{"raw packet io is unimplemented"};
        }
    };

    /// create native vpn platform
    std::shared_ptr<Platform> MakeNativePlatform(llarp::Context* ctx);

}  // namespace llarp::vpn
