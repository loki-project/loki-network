#include "win32.hpp"

#include <llarp/win32/windivert.hpp>
#include <llarp/win32/wintun.hpp>

#include <fmt/core.h>

namespace llarp::win32
{
    namespace
    {
        template <typename T>
        std::string ip_to_string(T ip)
        {
            return var::visit([](auto&& ip) { return ip.to_string(); }, ip);
        }
    }  // namespace

    void VPNPlatform::make_route(std::string ip, std::string gw, std::string cmd)
    {
        llarp::win32::Exec("route.exe", fmt::format("{} {} MASK 255.255.255.255 {} METRIC {}", cmd, ip, gw, m_Metric));
    }

    void VPNPlatform::default_route_via_interface(NetworkInterface& vpn, std::string cmd)
    {
        // route hole for loopback bacause god is dead on windows
        llarp::win32::Exec("route.exe", fmt::format("{} 127.0.0.0 MASK 255.0.0.0 0.0.0.0", cmd));
        // set up ipv4 routes
        route_via_interface(vpn, "0.0.0.0", "128.0.0.0", cmd);
        route_via_interface(vpn, "128.0.0.0", "128.0.0.0", cmd);
    }

    void VPNPlatform::route_via_interface(NetworkInterface& vpn, std::string addr, std::string mask, std::string cmd)
    {
        const auto& info = vpn.interface_info();
        auto ifaddr = ip_to_string(info[0]);
        // this changes the last 1 to a 0 so that it routes over the interface
        // this is required because windows is idiotic af
        ifaddr.back()--;
        llarp::win32::Exec("route.exe", fmt::format("{} {} MASK {} {} METRIC {}", cmd, addr, mask, ifaddr, m_Metric));
    }

    void VPNPlatform::add_route(oxen::quic::Address ip, oxen::quic::Address gateway)
    {
        make_route(ip.to_string(), gateway.to_string(), "ADD");
    }

    void VPNPlatform::delete_route(oxen::quic::Address ip, oxen::quic::Address gateway)
    {
        make_route(ip.to_string(), gateway.to_string(), "DELETE");
    }

    void VPNPlatform::add_route_via_interface(NetworkInterface& vpn, IPRange range)
    {
        route_via_interface(vpn, range.BaseAddressString(), range.NetmaskString(), "ADD");
    }

    void VPNPlatform::delete_route_via_interface(NetworkInterface& vpn, IPRange range)
    {
        route_via_interface(vpn, range.BaseAddressString(), range.NetmaskString(), "DELETE");
    }

    std::vector<oxen::quic::Address> VPNPlatform::get_non_interface_gateways(NetworkInterface& vpn)
    {
        std::set<oxen::quic::Address> gateways;

        const auto ifaddr = vpn.interface_info()[0];
        for (const auto& iface : Net().all_network_interfaces())
        {
            if (not iface._gateway)
                continue;

            bool b = true;

            for (const auto& range : iface.addrs)
            {
                if (not range.contains(ifaddr))
                    b = false;
            }
            // TODO: FIXME
            if (b)
                throw std::runtime_error{"FIXME ALREADY"};
            // gateways.emplace(*iface.gateway);
        }
        return {gateways.begin(), gateways.end()};
    }

    void VPNPlatform::add_default_route_via_interface(NetworkInterface& vpn)
    {
        // kill ipv6
        llarp::win32::Exec(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            "-Command (Disable-NetAdapterBinding -Name \"* \" -ComponentID ms_tcpip6)");

        default_route_via_interface(vpn, "ADD");
    }

    void VPNPlatform::delete_default_route_via_interface(NetworkInterface& vpn)
    {
        // restore ipv6
        llarp::win32::Exec(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            "-Command (Enable-NetAdapterBinding -Name \"* \" -ComponentID ms_tcpip6)");

        default_route_via_interface(vpn, "DELETE");
    }

    std::shared_ptr<NetworkInterface> VPNPlatform::obtain_interface(InterfaceInfo info, Router* router)
    {
        return wintun::make_interface(std::move(info), router);
    }

    std::shared_ptr<I_Packet_IO> VPNPlatform::create_packet_io(
        unsigned int ifindex, const std::optional<oxen::quic::Address>& dns_upstream_src)
    {
        // we only want do this on all interfaes with windivert
        if (ifindex)
            throw std::invalid_argument{
                "cannot create packet io on explicitly specified interface, not currently "
                "supported on "
                "windows (yet)"};

        uint16_t upstream_src_port = dns_upstream_src ? dns_upstream_src->port() : 0;
        std::string udp_filter = upstream_src_port != 0
            ? fmt::format("( udp.DstPort == 53 and udp.SrcPort != {} )", upstream_src_port)
            : "udp.DstPort == 53";

        auto filter = "outbound and ( " + udp_filter + " or tcp.DstPort == 53 )";

        // TESTNET:
        return WinDivert::make_interceptor(filter, [router = _ctx->router] { /* router->TriggerPump(); */ });
    }
}  // namespace llarp::win32
