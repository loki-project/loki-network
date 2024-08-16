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
                throw std::runtime_error{"getifaddrs(): {}"_format(strerror(errno))};

            for (auto next = addrs; next; next = next->ifa_next)
                visit(next);

            freeifaddrs(addrs);
        }

      public:
        std::string loopback_interface_name() const override
        {
            std::string ifname;

            iter_all([&ifname](ifaddrs* i) {
                if (i and i->ifa_addr and i->ifa_addr->sa_family == AF_INET)
                {
                    const oxen::quic::Address addr{i->ifa_addr};

                    if (addr.is_loopback())
                        ifname = i->ifa_name;
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

        std::optional<IPRange> find_free_range() const override
        {
            std::list<IPRange> current_ranges;

            iter_all([&current_ranges](ifaddrs* i) {
                if (i and i->ifa_addr and i->ifa_addr->sa_family == AF_INET)
                {
                    oxen::quic::Address addr{i->ifa_addr};
                    uint8_t m = reinterpret_cast<sockaddr_in*>(i->ifa_netmask)->sin_addr.s_addr;
                    current_ranges.emplace_back(std::move(addr), std::move(m));
                }
            });

            return IPRange::find_private_range(current_ranges);
        }

        std::optional<int> get_interface_index(ip_v ip) const override
        {
            std::optional<int> ret = std::nullopt;
            oxen::quic::Address ip_addr{};

            int counter = 0;

            if (auto* maybe = std::get_if<ipv4>(&ip))
                ip_addr = oxen::quic::Address{*maybe, 0};
            else if (auto* maybe = std::get_if<ipv6>(&ip))
                ip_addr = oxen::quic::Address{*maybe, 0};

            iter_all([&ret, &counter, ip_addr](ifaddrs* i) {
                if (ret)
                    return;

                if (not(i and i->ifa_addr))
                    return;

                counter += 1;

                const oxen::quic::Address addr{i->ifa_addr};

                if (addr == ip_addr)
                    ret = counter;
            });

            return ret;
        }

        std::optional<std::string> FindFreeTun() const override
        {
            int num = 0;

            while (num < 255)
            {
                std::string ifname = fmt::format("lokitun{}", num);
                if (get_interface_addr(ifname, AF_INET) == std::nullopt)
                    return ifname;
                num++;
            }

            return std::nullopt;
        }

        std::optional<oxen::quic::Address> get_interface_addr(std::string_view ifname, int af) const override
        {
            std::optional<oxen::quic::Address> addr;

            iter_all([&addr, af, ifname = std::string{ifname}](ifaddrs* i) {
                if (addr)
                    return;
                if (i and i->ifa_addr and i->ifa_addr->sa_family == af and i->ifa_name == ifname)
                    addr = i->ifa_addr;
            });

            return addr;
        }

        std::optional<oxen::quic::Address> all_interfaces(oxen::quic::Address fallback) const override
        {
            std::optional<oxen::quic::Address> found;

            iter_all([fallback, &found](ifaddrs* i) {
                if (found)
                    return;

                if (i == nullptr or i->ifa_addr == nullptr)
                    return;

                auto& sa_fam = i->ifa_addr->sa_family;

                if (sa_fam == AF_INET and not fallback.is_ipv4())
                    return;

                if (sa_fam == AF_INET6 and not fallback.is_ipv6())
                    return;

                oxen::quic::Address addr{i->ifa_addr};

                if (addr == fallback)
                    found = addr;
            });

            // when we cannot find an address but we are looking for 0.0.0.0 just default to the old style
            if (not found and fallback.is_any_addr())
                found = wildcard(fallback.is_ipv4() ? AF_INET : AF_INET6);

            return found;
        }

        bool has_interface_address(ip_v ip) const override
        {
            bool found{false};
            oxen::quic::Address ip_addr{};

            if (auto* maybe = std::get_if<ipv4>(&ip))
                ip_addr = oxen::quic::Address{*maybe, 0};
            else if (auto* maybe = std::get_if<ipv6>(&ip))
                ip_addr = oxen::quic::Address{*maybe, 0};

            iter_all([&found, ip_addr](ifaddrs* i) {
                if (found)
                    return;

                if (not(i and i->ifa_addr))
                    return;

                const oxen::quic::Address addr{i->ifa_addr};

                found = addr == ip_addr;
            });

            return found;
        }

        std::vector<InterfaceInfo> all_network_interfaces() const override
        {
            std::unordered_map<std::string, InterfaceInfo> ifmap;

            iter_all([&ifmap](ifaddrs* i) {
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

                oxen::quic::Address addr{i->ifa_addr};
                uint8_t m = reinterpret_cast<sockaddr_in*>(i->ifa_netmask)->sin_addr.s_addr;

                ent.addrs.emplace_back(std::move(addr), m);
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
