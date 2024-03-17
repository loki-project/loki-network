#pragma once

#include "common.hpp"
#include "platform.hpp"

#include <llarp.hpp>

#include <unistd.h>

#include <cstdio>

namespace llarp::vpn
{
    class AndroidInterface : public NetworkInterface
    {
        const int m_fd;

      public:
        AndroidInterface(InterfaceInfo info, int fd) : NetworkInterface{std::move(info)}, m_fd{fd}
        {
            if (m_fd == -1)
                throw std::runtime_error("Error opening AndroidVPN layer FD: " + std::string{strerror(errno)});
        }

        virtual ~AndroidInterface()
        {
            if (m_fd != -1)
                ::close(m_fd);
        }

        int PollFD() const override
        {
            return m_fd;
        }

        net::IPPacket ReadNextPacket() override
        {
            std::vector<uint8_t> pkt;
            pkt.reserve(net::IPPacket::MaxSize);
            const auto n = read(m_fd, pkt.data(), pkt.capacity());
            pkt.resize(std::min(std::max(ssize_t{}, n), static_cast<ssize_t>(pkt.capacity())));
            return net::IPPacket{std::move(pkt)};
        }

        bool WritePacket(net::IPPacket pkt) override
        {
            const auto sz = write(m_fd, pkt.data(), pkt.size());
            if (sz <= 0)
                return false;
            return sz == static_cast<ssize_t>(pkt.size());
        }
    };

    class AndroidRouteManager : public AbstractRouteManager
    {
        void add_route(oxen::quic::Address, oxen::quic::Address) override{};

        void delete_route(oxen::quic::Address, oxen::quic::Address) override{};

        void add_default_route_via_interface(NetworkInterface&) override{};

        void delete_default_route_via_interface(NetworkInterface&) override{};

        void add_route_via_interface(NetworkInterface&, IPRange) override{};

        void delete_route_via_interface(NetworkInterface&, IPRange) override{};

        std::vector<oxen::quic::Address> get_non_interface_gateways(NetworkInterface&) override
        {
            return std::vector<oxen::quic::Address>{};
        };
    };

    class AndroidPlatform : public Platform
    {
        const int fd;
        AndroidRouteManager _route_manager{};

      public:
        AndroidPlatform(llarp::Context* ctx) : fd{ctx->androidFD}
        {}

        std::shared_ptr<NetworkInterface> ObtainInterface(InterfaceInfo info, Router*) override
        {
            return std::make_shared<AndroidInterface>(std::move(info), fd);
        }
        AbstractRouteManager& RouteManager() override
        {
            return _route_manager;
        }
    };

}  // namespace llarp::vpn
