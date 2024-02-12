#pragma once

#include "common.hpp"
#include "platform.hpp"

#include <llarp.hpp>
#include <llarp/net/net.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/fs.hpp>
#include <llarp/util/str.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <oxenc/endian.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <exception>

namespace llarp::vpn
{
    struct in6_ifreq
    {
        in6_addr addr;
        uint32_t prefixlen;
        unsigned int ifindex;
    };

    class LinuxInterface : public NetworkInterface
    {
        const int _fd;

       public:
        LinuxInterface(InterfaceInfo info) : NetworkInterface{std::move(info)}, _fd{::open("/dev/net/tun", O_RDWR)}
        {
            if (_fd == -1)
                throw std::runtime_error("cannot open /dev/net/tun " + std::string{strerror(errno)});

            ifreq ifr{};
            in6_ifreq ifr6{};

            ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
            std::copy_n(_info.ifname.c_str(), std::min(_info.ifname.size(), sizeof(ifr.ifr_name)), ifr.ifr_name);

            if (::ioctl(_fd, TUNSETIFF, &ifr) == -1)
                throw std::runtime_error("cannot set interface name: " + std::string{strerror(errno)});

            IOCTL control{AF_INET};

            control.ioctl(SIOCGIFFLAGS, &ifr);
            const int flags = ifr.ifr_flags;

            control.ioctl(SIOCGIFINDEX, &ifr);
            _info.index = ifr.ifr_ifindex;

            for (const auto& ifaddr : _info.addrs)
            {
                auto& range = ifaddr.range;

                if (ifaddr.fam == AF_INET)
                {
                    ifr.ifr_addr.sa_family = AF_INET;
                    auto in4 = range.address().in4();
                    std::memcpy(
                        &((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr, &in4.sin_addr.s_addr, sizeof(sockaddr));

                    control.ioctl(SIOCSIFADDR, &ifr);

                    ((sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr =
                        oxenc::load_host_to_big<unsigned int>(&range.mask());
                    control.ioctl(SIOCSIFNETMASK, &ifr);
                }
                if (ifaddr.fam == AF_INET6)
                {
                    auto in6 = range.address().in6();

                    std::memcpy(&ifr6.addr, &in6.sin6_addr, sizeof(in6.sin6_addr));

                    ifr6.prefixlen = llarp::bits::count_bits(range.mask());
                    ifr6.ifindex = _info.index;
                    try
                    {
                        IOCTL{AF_INET6}.ioctl(SIOCSIFADDR, &ifr6);
                    }
                    catch (const std::exception& e)
                    {
                        log::error(logcat, "IPv6 not allowed on this system: {}", e.what());
                    }
                }
            }

            ifr.ifr_flags = static_cast<short>(flags | IFF_UP | IFF_NO_PI);
            control.ioctl(SIOCSIFFLAGS, &ifr);
        }

        ~LinuxInterface() override
        {
            ::close(_fd);
        }

        int PollFD() const override
        {
            return _fd;
        }

        IPPacket ReadNextPacket() override
        {
            std::vector<uint8_t> buf;
            buf.resize(MAX_PACKET_SIZE);
            const auto sz = read(_fd, buf.data(), buf.capacity());
            if (sz < 0)
            {
                if (errno == EAGAIN or errno == EWOULDBLOCK)
                {
                    errno = 0;
                    return IPPacket{};
                }
                throw std::error_code{errno, std::system_category()};
            }

            buf.resize(sz);

            return IPPacket{std::move(buf)};
        }

        bool WritePacket(IPPacket pkt) override
        {
            const auto sz = write(_fd, pkt.data(), pkt.size());
            if (sz <= 0)
                return false;
            return sz == static_cast<ssize_t>(pkt.size());
        }
    };

    class LinuxRouteManager : public AbstractRouteManager
    {
        const int fd;

        enum class GatewayMode
        {
            eFirstHop,
            eLowerDefault,
            eUpperDefault
        };

        struct NLRequest
        {
            nlmsghdr n;
            rtmsg r;
            char buf[4096];

            void AddData(int type, const void* data, int alen)
            {
#define NLMSG_TAIL(nmsg) ((struct rtattr*)(((intptr_t)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

                int len = RTA_LENGTH(alen);
                rtattr* rta;
                if (NLMSG_ALIGN(n.nlmsg_len) + RTA_ALIGN(len) > sizeof(*this))
                {
                    throw std::length_error{"nlrequest add data overflow"};
                }
                rta = NLMSG_TAIL(&n);
                rta->rta_type = type;
                rta->rta_len = len;
                if (alen)
                {
                    memcpy(RTA_DATA(rta), data, alen);
                }
                n.nlmsg_len = NLMSG_ALIGN(n.nlmsg_len) + RTA_ALIGN(len);
#undef NLMSG_TAIL
            }
        };

        /* Helper structure for ip address data and attributes */
        struct _inet_addr
        {
            unsigned char family;
            unsigned char bitlen;
            unsigned char data[sizeof(struct in6_addr)];

            _inet_addr(oxen::quic::Address addr)
            {
                const auto& v4 = addr.is_ipv4();

                family = (v4) ? AF_INET : AF_INET6;
                bitlen = (v4) ? 32 : 128;
                std::memcpy(data, addr.host().data(), (v4) ? 4 : 16);
            }

            _inet_addr(net::ipv4addr_t addr, size_t bits = 32)
            {
                family = AF_INET;
                bitlen = bits;
                std::memcpy(data, &addr.n, 4);
            }

            _inet_addr(net::ipv6addr_t addr, size_t bits = 128)
            {
                family = AF_INET6;
                bitlen = bits;
                std::memcpy(data, &addr.n, 16);
            }
        };

        void make_blackhole(int cmd, int flags, int af)
        {
            NLRequest nl_request{};
            /* Initialize request structure */
            nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
            nl_request.n.nlmsg_flags = NLM_F_REQUEST | flags;
            nl_request.n.nlmsg_type = cmd;
            nl_request.n.nlmsg_pid = getpid();
            nl_request.r.rtm_family = af;
            nl_request.r.rtm_table = RT_TABLE_LOCAL;
            nl_request.r.rtm_type = RTN_BLACKHOLE;
            nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE;
            if (af == AF_INET)
            {
                uint32_t addr{};
                nl_request.AddData(RTA_DST, &addr, sizeof(addr));
            }
            else
            {
                uint128_t addr{};
                nl_request.AddData(RTA_DST, &addr, sizeof(addr));
            }
            send(fd, &nl_request, sizeof(nl_request), 0);
        }

        void make_route(int cmd, int flags, const _inet_addr& dst, const _inet_addr& gw, GatewayMode mode, int if_idx)
        {
            NLRequest nl_request{};

            /* Initialize request structure */
            nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
            nl_request.n.nlmsg_flags = NLM_F_REQUEST | flags;
            nl_request.n.nlmsg_type = cmd;
            nl_request.n.nlmsg_pid = getpid();
            nl_request.r.rtm_family = dst.family;
            nl_request.r.rtm_table = RT_TABLE_MAIN;
            if (if_idx)
            {
                nl_request.r.rtm_scope = RT_SCOPE_LINK;
            }
            else
            {
                nl_request.r.rtm_scope = RT_SCOPE_NOWHERE;
            }
            /* Set additional flags if NOT deleting route */
            if (cmd != RTM_DELROUTE)
            {
                nl_request.r.rtm_protocol = RTPROT_BOOT;
                nl_request.r.rtm_type = RTN_UNICAST;
            }

            nl_request.r.rtm_family = dst.family;
            nl_request.r.rtm_dst_len = dst.bitlen;
            nl_request.r.rtm_scope = 0;

            /* Set gateway */
            if (gw.bitlen != 0 and dst.family == AF_INET)
            {
                nl_request.AddData(RTA_GATEWAY, &gw.data, gw.bitlen / 8);
            }
            nl_request.r.rtm_family = gw.family;
            if (mode == GatewayMode::eFirstHop)
            {
                nl_request.AddData(RTA_DST, &dst.data, dst.bitlen / 8);
                /* Set interface */
                nl_request.AddData(RTA_OIF, &if_idx, sizeof(int));
            }
            if (mode == GatewayMode::eUpperDefault)
            {
                if (dst.family == AF_INET)
                {
                    nl_request.AddData(RTA_DST, &dst.data, sizeof(uint32_t));
                }
                else
                {
                    nl_request.AddData(RTA_OIF, &if_idx, sizeof(int));
                    nl_request.AddData(RTA_DST, &dst.data, sizeof(in6_addr));
                }
            }
            /* Send message to the netlink */
            send(fd, &nl_request, sizeof(nl_request), 0);
        }

        void default_route_via_interface(NetworkInterface& vpn, int cmd, int flags)
        {
            const auto& info = vpn.Info();

            const auto maybe = Net().get_interface_addr(info.ifname);
            if (not maybe)
                throw std::runtime_error{"we dont have our own network interface?"};

            const _inet_addr gateway{*maybe};
            const _inet_addr lower{ToNet(ipaddr_ipv4_bits(0, 0, 0, 0)), 1};
            const _inet_addr upper{ToNet(ipaddr_ipv4_bits(128, 0, 0, 0)), 1};

            make_route(cmd, flags, lower, gateway, GatewayMode::eLowerDefault, info.index);
            make_route(cmd, flags, upper, gateway, GatewayMode::eUpperDefault, info.index);

            if (const auto maybe6 = Net().get_interface_ipv6_addr(info.ifname))
            {
                const _inet_addr gateway6{*maybe6};
                for (const std::string str : {"::", "4000::", "8000::", "c000::"})
                {
                    const _inet_addr hole6{net::ipv6addr_t::from_string(str), 2};
                    make_route(cmd, flags, hole6, gateway6, GatewayMode::eUpperDefault, info.index);
                }
            }
        }

        void route_via_interface(int cmd, int flags, NetworkInterface& vpn, IPRange range)
        {
            const auto& info = vpn.Info();
            if (range.is_ipv4())
            {
                const auto maybe = Net().get_interface_addr(info.ifname);
                if (not maybe)
                    throw std::runtime_error{"we dont have our own network interface?"};

                const auto gateway = var::visit([](auto&& ip) { return _inet_addr{ip}; }, maybe->getIP());

                const _inet_addr addr{range.address()};

                make_route(cmd, flags, addr, gateway, GatewayMode::eUpperDefault, info.index);
            }
            else
            {
                const auto maybe = Net().get_interface_ipv6_addr(info.ifname);

                if (not maybe)
                    throw std::runtime_error{"we dont have our own network interface?"};

                const _inet_addr gateway{*maybe};
                const _inet_addr addr{range.address()};

                make_route(cmd, flags, addr, gateway, GatewayMode::eUpperDefault, info.index);
            }
        }

        void make_route(int cmd, int flags, oxen::quic::Address ip, oxen::quic::Address gateway)
        {
            make_route(cmd, flags, _inet_addr{ip}, _inet_addr{gateway}, GatewayMode::eFirstHop, 0);
        }

       public:
        LinuxRouteManager() : fd{socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)}
        {
            if (fd == -1)
                throw std::runtime_error{"failed to make netlink socket"};
        }

        ~LinuxRouteManager()
        {
            close(fd);
        }

        void add_route(oxen::quic::Address ip, oxen::quic::Address gateway) override
        {
            make_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, ip, gateway);
        }

        void delete_route(oxen::quic::Address ip, oxen::quic::Address gateway) override
        {
            make_route(RTM_DELROUTE, 0, ip, gateway);
        }

        void add_default_route_via_interface(NetworkInterface& vpn) override
        {
            default_route_via_interface(vpn, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL);
        }

        void delete_default_route_via_interface(NetworkInterface& vpn) override
        {
            default_route_via_interface(vpn, RTM_DELROUTE, 0);
        }

        void add_route_via_interface(NetworkInterface& vpn, IPRange range) override
        {
            route_via_interface(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, vpn, range);
        }

        void delete_route_via_interface(NetworkInterface& vpn, IPRange range) override
        {
            route_via_interface(RTM_DELROUTE, 0, vpn, range);
        }

        std::vector<oxen::quic::Address> get_non_interface_gateways(NetworkInterface& vpn) override
        {
            const auto& ifname = vpn.Info().ifname;
            std::vector<oxen::quic::Address> gateways{};

            std::ifstream inf{"/proc/net/route"};
            for (std::string line; std::getline(inf, line);)
            {
                const auto parts = split(line, "\t");
                if (parts[1].find_first_not_of('0') == std::string::npos and parts[0] != ifname)
                {
                    const auto& ip = parts[2];
                    if ((ip.size() == sizeof(uint32_t) * 2) and oxenc::is_hex(ip))
                    {
                        std::string buf;
                        oxenc::from_hex(ip.begin(), ip.end(), buf.data());
                        oxen::quic::Address addr{buf, 0};
                        gateways.push_back(std::move(addr));
                    }
                }
            }
            return gateways;
        }

        void add_blackhole() override
        {
            make_blackhole(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, AF_INET);
            make_blackhole(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, AF_INET6);
        }

        void delete_blackhole() override
        {
            make_blackhole(RTM_DELROUTE, 0, AF_INET);
            make_blackhole(RTM_DELROUTE, 0, AF_INET6);
        }
    };

    class LinuxPlatform : public Platform
    {
        LinuxRouteManager _routeManager{};

       public:
        std::shared_ptr<NetworkInterface> ObtainInterface(InterfaceInfo info, Router*) override
        {
            return std::make_shared<LinuxInterface>(std::move(info));
        };

        AbstractRouteManager& RouteManager() override
        {
            return _routeManager;
        }
    };

}  // namespace llarp::vpn
