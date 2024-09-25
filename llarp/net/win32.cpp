#include "ip.hpp"
#include "ip_range.hpp"
#include "net.hpp"
#include "net_if.hpp"

#include <llarp/constants/platform.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/str.hpp>
#include <llarp/win32/exception.hpp>

#include <iphlpapi.h>

#include <cstdio>
#include <list>
#include <stdexcept>
#include <type_traits>

namespace llarp::net
{
    static auto logcat = log::Cat("win32.net");

    class Platform_Impl : public Platform
    {
        /// visit all adapters (not addresses). windows serves net info per adapter unlink posix
        /// which gives a list of all distinct addresses.
        template <typename Visit_t>
        void iter_adapters(Visit_t&& visit, int af = AF_UNSPEC) const
        {
            ULONG err;
            ULONG sz = 15000;  // MS-recommended so that it "never fails", but often fails with a
                               // too large error.
            std::unique_ptr<uint8_t[]> ptr;
            PIP_ADAPTER_ADDRESSES addr;
            int tries = 0;
            do
            {
                ptr = std::make_unique<uint8_t[]>(sz);
                addr = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ptr.get());
                err = GetAdaptersAddresses(af, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, nullptr, addr, &sz);
            } while (err == ERROR_BUFFER_OVERFLOW and ++tries < 4);

            if (err != ERROR_SUCCESS)
                throw llarp::win32::error{err, "GetAdaptersAddresses()"};

            for (; addr; addr = addr->Next)
                visit(addr);
        }

        template <typename adapter_t>
        bool adapter_has_ip(adapter_t* a, ipaddr_t ip) const
        {
            for (auto* addr = a->FirstUnicastAddress; addr; addr = addr->Next)
            {
                oxen::quic::Address saddr{*addr->Address.lpSockaddr};

                log::debug(logcat, "'{}' has address '{}", a->AdapterName, saddr);
                if (saddr.getIP() == ip)
                    return true;
            }
            return false;
        }

        template <typename adapter_t>
        bool adapter_has_fam(adapter_t* a, int af) const
        {
            for (auto* addr = a->FirstUnicastAddress; addr; addr = addr->Next)
            {
                oxen::quic::Address saddr{*addr->Address.lpSockaddr};
                if (saddr.Family() == af)
                    return true;
            }
            return false;
        }

      public:
        std::optional<int> get_interface_index(ip ip) const override
        {
            std::optional<int> found;
            int af{AF_INET};

            if (std::holds_alternative<ipv6>(ip))
                af = AF_INET6;

            iter_adapters(
                [&found, ip, this](auto* adapter) {
                    if (found)
                        return;

                    log::debug(
                        logcat,
                        "Visit adapter looking for '{}': '{} idx={}",
                        ip,
                        adapter->AdapterName,
                        adapter->IfIndex);

                    if (adapter_has_ip(adapter, ip))
                    {
                        found = adapter->IfIndex;
                    }
                },
                af);

            return found;
        }

        std::optional<oxen::quic::Address> get_interface_addr(std::string_view name, int af) const override
        {
            std::optional<oxen::quic::Address> found;

            iter_adapters([name = std::string{name}, af, &found, this](auto* a) {
                if (found)
                    return;
                if (std::string{a->AdapterName} != name)
                    return;

                if (adapter_has_fam(a, af))
                    found = oxen::quic::Address{*a->FirstUnicastAddress->Address.lpSockaddr};
            });

            return found;
        }

        std::optional<oxen::quic::Address> all_interfaces(oxen::quic::Address fallback) const override
        {
            (void)fallback;
            // windows seems to not give a shit about source address
            return oxen::quic::Address{};
        }

        std::optional<std::string> find_free_tun(int) const override { return "lokitun0"; }

        std::optional<oxen::quic::Address> get_best_public_address(bool, uint16_t) const override
        {
            // TODO: implement me ?
            return std::nullopt;
        }

        if_info find_free_interface(int af) const override { return if_info{af}; }

        std::optional<IPRange> find_free_range(bool ipv6_enabled) const override
        {
            std::list<IPRange> currentRanges;

            iter_adapters([&currentRanges](auto* i) {
                for (auto* addr = i->FirstUnicastAddress; addr; addr = addr->Next)
                {
                    oxen::quic::Address saddr{*addr->Address.lpSockaddr};

                    bool is_ipv6 = addr->Address.lpSockaddr->sa_family == AF_INET6 ? true : false;

                    // TOFIX: wtf is this
                    uint8_t m = is_ipv6 ? reinterpret_cast<sockaddr_in6*>(*addr->Address.lpSockaddr)->sin6_addr.s6_addr
                                        : reinterpret_cast<sockaddr_in*>(*addr->Address.lpSockaddr)->sin_addr.s_addr;

                    currentRanges.emplace_back(std::move(saddr), m);
                }
            });

            return IPRange::find_private_range(currentRanges);
        }

        std::string loopback_interface_name() const override
        {
            // todo: implement me? does windows even have a loopback?
            return "";
        }

        bool has_interface_address(ip ip) const override { return get_interface_index(ip) != std::nullopt; }

        std::vector<InterfaceInfo> all_network_interfaces() const override
        {
            std::vector<InterfaceInfo> all;
            for (int af : {AF_INET, AF_INET6})
                iter_adapters(
                    [&all](auto* a) {
                        auto& cur = all.emplace_back();
                        cur.index = a->IfIndex;
                        cur.name = a->AdapterName;
                        for (auto* addr = a->FirstUnicastAddress; addr; addr = addr->Next)
                        {
                            SockAddr saddr{*addr->Address.lpSockaddr};
                            cur.addrs.emplace_back(
                                saddr.asIPv6(),
                                ipaddr_netmask_bits(addr->OnLinkPrefixLength, addr->Address.lpSockaddr->sa_family));
                        }
                        if (auto* addr = a->FirstGatewayAddress)
                        {
                            SockAddr gw{*addr->Address.lpSockaddr};
                            cur.gateway = gw.getIP();
                        }
                    },
                    af);
            return all;
        }
    };

    const Platform_Impl g_plat{};

    const Platform* Platform::Default_ptr()
    {
        return &g_plat;
    }
}  // namespace llarp::net
