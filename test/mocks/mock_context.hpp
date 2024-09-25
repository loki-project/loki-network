#pragma once
#include <llarp.hpp>

#include "mock_network.hpp"
#include "mock_router.hpp"
#include "mock_vpn.hpp"

namespace mocks
{
  class MockContext : public llarp::Context
  {
    const Network& _net;

   public:
    MockContext(const Network& net) : llarp::Context{}, _net{net}
    {
      loop = std::shared_ptr<llarp::EventLoop>{const_cast<Network*>(&_net), [](Network*) {}};
    }

    std::shared_ptr<llarp::Router>
    makeRouter(const std::shared_ptr<llarp::EventLoop>&) override
    {
      return std::static_pointer_cast<llarp::Router>(
          std::make_shared<MockRouter>(_net, makeVPNPlatform()));
    }

    std::shared_ptr<llarp::vpn::Platform>
    makeVPNPlatform() override
    {
      return std::static_pointer_cast<llarp::vpn::Platform>(std::make_shared<MockVPN>(_net));
    }

    std::shared_ptr<llarp::NodeDB>
    makeNodeDB() override
    {
      return std::make_shared<llarp::NodeDB>();
    }
  };

}  // namespace mocks
