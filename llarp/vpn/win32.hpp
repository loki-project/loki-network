#pragma once

#include "platform.hpp"

#include <llarp.hpp>
#include <llarp/router/router.hpp>
#include <llarp/win32/exec.hpp>

#include <winsock2.h>

#include <windows.h>

#include <iphlpapi.h>

namespace llarp::win32
{
    using namespace llarp::vpn;
    class VPNPlatform : public Platform, public AbstractRouteManager
    {
        llarp::Context* const _ctx;
        const int m_Metric{2};

        const auto& Net() const { return _ctx->router->net(); }

        void make_route(std::string ip, std::string gw, std::string cmd);

        void default_route_via_interface(NetworkInterface& vpn, std::string cmd);

        void route_via_interface(NetworkInterface& vpn, std::string addr, std::string mask, std::string cmd);

      public:
        VPNPlatform(const VPNPlatform&) = delete;
        VPNPlatform(VPNPlatform&&) = delete;

        VPNPlatform(llarp::Context* ctx) : Platform{}, _ctx{ctx} {}

        ~VPNPlatform() override = default;

        void add_route(oxen::quic::Address ip, oxen::quic::Address gateway) override;

        void delete_route(oxen::quic::Address ip, oxen::quic::Address gateway) override;

        void add_route_via_interface(NetworkInterface& vpn, IPRange range) override;

        void delete_route_via_interface(NetworkInterface& vpn, IPRange range) override;

        std::vector<oxen::quic::Address> get_non_interface_gateways(NetworkInterface& vpn) override;

        void add_default_route_via_interface(NetworkInterface& vpn) override;

        void delete_default_route_via_interface(NetworkInterface& vpn) override;

        std::shared_ptr<NetworkInterface> ObtainInterface(InterfaceInfo info, Router* router) override;

        std::shared_ptr<I_Packet_IO> create_packet_io(
            unsigned int ifindex, const std::optional<oxen::quic::Address>& dns_upstream_src) override;

        AbstractRouteManager& RouteManager() override { return *this; }
    };

}  // namespace llarp::win32
