#include "ip_range.hpp"
#include "net.hpp"
#include "net_if.hpp"

#include <stdexcept>

#ifdef ANDROID
#include <llarp/android/ifaddrs.h>
#else
#include <ifaddrs.h>
#endif

#include <oxen/quic/address.hpp>

#include <list>

namespace llarp::net
{
    class Platform_Impl : public Platform
    {
        template <typename Visit_t>
        void iter_all(Visit_t&& visit) const
        {
            ifaddrs* addrs{nullptr};
            if (getifaddrs(&addrs))
                throw std::runtime_error{fmt::format("getifaddrs(): {}", strerror(errno))};

            for (auto next = addrs; next; next = next->ifa_next)
                visit(next);

            freeifaddrs(addrs);
        }

       public:
        std::string LoopbackInterfaceName() const override
        {
            std::string ifname;
            iter_all([this, &ifname](auto i) {
                if (i and i->ifa_addr and i->ifa_addr->sa_family == AF_INET)
                {
                    const SockAddr_deprecated addr{*i->ifa_addr};
                    if (IsLoopbackAddress(addr.getIP()))
                    {
                        ifname = i->ifa_name;
                    }
                }
            });
            if (ifname.empty())
                throw std::runtime_error{"we have no ipv4 loopback interface for some ungodly reason"};
            return ifname;
        }

        std::optional<oxen::quic::Address> get_best_public_address(bool ipv4, uint16_t port) const override
        {
            std::optional<oxen::quic::Address> found;

            iter_all([&found, ipv4, port](ifaddrs* i) {
                if (found)
                    return;
                if (i and i->ifa_addr and i->ifa_addr->sa_family == (ipv4 ? AF_INET : AF_INET6))
                {
                    oxen::quic::Address a{i->ifa_addr};
                    if (a.is_public_ip())
                    {
                        a.set_port(port);
                        found = std::move(a);
                    }
                }
            });

            return found;
        }

        std::optional<IP_range_deprecated> FindFreeRange() const override
        {
            std::list<IP_range_deprecated> currentRanges;
            iter_all([&currentRanges](auto i) {
                if (i and i->ifa_addr and i->ifa_addr->sa_family == AF_INET)
                {
                    ipv4addr_t addr{reinterpret_cast<sockaddr_in*>(i->ifa_addr)->sin_addr.s_addr};
                    ipv4addr_t mask{reinterpret_cast<sockaddr_in*>(i->ifa_netmask)->sin_addr.s_addr};
                    currentRanges.emplace_back(IP_range_deprecated::FromIPv4(addr, mask));
                }
            });

            return IP_range_deprecated::FindPrivateRange(currentRanges);
        }

        std::optional<int> GetInterfaceIndex(ipaddr_t) const override
        {
            // todo: implement me
            return std::nullopt;
        }

        std::optional<std::string> FindFreeTun() const override
        {
            int num = 0;
            while (num < 255)
            {
                std::string ifname = fmt::format("lokitun{}", num);
                if (GetInterfaceAddr(ifname, AF_INET) == std::nullopt)
                    return ifname;
                num++;
            }
            return std::nullopt;
        }

        std::optional<SockAddr_deprecated> GetInterfaceAddr(std::string_view ifname, int af) const override
        {
            std::optional<SockAddr_deprecated> addr;
            iter_all([&addr, af, ifname = std::string{ifname}](auto i) {
                if (addr)
                    return;
                if (i and i->ifa_addr and i->ifa_addr->sa_family == af and i->ifa_name == ifname)
                    addr = llarp::SockAddr_deprecated{*i->ifa_addr};
            });
            return addr;
        }

        std::optional<SockAddr_deprecated> AllInterfaces(SockAddr_deprecated fallback) const override
        {
            std::optional<SockAddr_deprecated> found;
            iter_all([fallback, &found](auto i) {
                if (found)
                    return;
                if (i == nullptr or i->ifa_addr == nullptr)
                    return;
                if (i->ifa_addr->sa_family != fallback.Family())
                    return;
                SockAddr_deprecated addr{*i->ifa_addr};
                if (addr == fallback)
                    found = addr;
            });

            // 0.0.0.0 is used in our compat shim as our public ip so we check for that special case
            const auto zero = IP_range_deprecated::FromIPv4(0, 0, 0, 0, 8);
            // when we cannot find an address but we are looking for 0.0.0.0 just default to the old
            // style
            if (not found and (fallback.isIPv4() and zero.Contains(fallback.asIPv4())))
                found = Wildcard(fallback.Family());
            return found;
        }

        bool HasInterfaceAddress(ipaddr_t ip) const override
        {
            bool found{false};
            iter_all([&found, ip](auto i) {
                if (found)
                    return;

                if (not(i and i->ifa_addr))
                    return;
                const SockAddr_deprecated addr{*i->ifa_addr};
                found = addr.getIP() == ip;
            });
            return found;
        }
        std::vector<InterfaceInfo> AllNetworkInterfaces() const override
        {
            std::unordered_map<std::string, InterfaceInfo> ifmap;
            iter_all([&ifmap](auto* i) {
                if (i == nullptr or i->ifa_addr == nullptr)
                    return;

                const auto fam = i->ifa_addr->sa_family;
                if (fam != AF_INET and fam != AF_INET6)
                    return;

                auto& ent = ifmap[i->ifa_name];
                if (ent.name.empty())
                {
                    ent.name = i->ifa_name;
                    ent.index = if_nametoindex(i->ifa_name);
                }
                SockAddr_deprecated addr{*i->ifa_addr};
                SockAddr_deprecated mask{*i->ifa_netmask};
                ent.addrs.emplace_back(addr.asIPv6(), mask.asIPv6());
            });
            std::vector<InterfaceInfo> all;
            for (auto& [name, ent] : ifmap)
                all.emplace_back(std::move(ent));
            return all;
        }
    };

    const Platform_Impl g_plat{};

    const Platform* Platform::Default_ptr()
    {
        return &g_plat;
    }
}  // namespace llarp::net
