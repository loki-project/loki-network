#pragma once
#include <llarp/vpn/platform.hpp>
#include "mock_network.hpp"

namespace mocks
{
  class MockInterface : public llarp::vpn::NetworkInterface
  {
    int _pipes[2];

   public:
      MockInterface(llarp::vpn::InterfaceInfo info) : llarp::vpn::NetworkInterface{std::move(info)}
    {
      if (pipe(_pipes))
        throw std::runtime_error{strerror(errno)};
    }

    virtual ~MockInterface()
    {
      close(_pipes[1]);
    }

    int
    PollFD() const override
    {
      return _pipes[0];
    };

    llarp::net::IPPacket
    ReadNextPacket() override
    {
      return llarp::net::IPPacket{};
    };

    bool WritePacket(llarp::net::IPPacket) override
    {
      return true;
    }
  };

  class MockVPN : public llarp::vpn::Platform, public llarp::vpn::IRouteManager
  {
    const Network& _net;

   public:
    MockVPN(const Network& net) : llarp::vpn::Platform{}, llarp::vpn::IRouteManager{}, _net{net}
    {}

    virtual std::shared_ptr<llarp::vpn::NetworkInterface>
    obtain_interface(llarp::vpn::InterfaceInfo info, llarp::Router*) override
    {
      return std::make_shared<MockInterface>(info);
    };

    const llarp::net::Platform*
    Net_ptr() const override
    {
      return &_net;
    };

    void AddRoute(llarp::net::ipaddr_t, llarp::net::ipaddr_t) override{};

    void DelRoute(llarp::net::ipaddr_t, llarp::net::ipaddr_t) override{};

    void AddDefaultRouteViaInterface(llarp::vpn::NetworkInterface&) override{};

    void DelDefaultRouteViaInterface(llarp::vpn::NetworkInterface&) override{};

    void
    AddRouteViaInterface(llarp::vpn::NetworkInterface&, llarp::IPRange) override{};

    void
    DelRouteViaInterface(llarp::vpn::NetworkInterface&, llarp::IPRange) override{};

    std::vector<llarp::net::ipaddr_t> GetGatewaysNotOnInterface(llarp::vpn::NetworkInterface&) override
    {
      return std::vector<llarp::net::ipaddr_t>{};
    };

    /// get owned ip route manager for managing routing table
    virtual llarp::vpn::IRouteManager&
    RouteManager() override
    {
      return *this;
    };
  };
}  // namespace mocks
