#include "tunnel.hpp"

#include <llarp/router/router.hpp>

namespace llarp
{
    QUICTunnel::QUICTunnel(Router& r)
        : _router{r},
          _q{std::make_unique<oxen::quic::Network>(_router.loop()->_loop)},
          _tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_keys("", "")}
    {}

    std::shared_ptr<QUICTunnel> QUICTunnel::make(Router& r)
    {
        std::shared_ptr<QUICTunnel> q{new QUICTunnel(r)};
        return q;
    }

    std::shared_ptr<oxen::quic::Endpoint> QUICTunnel::startup_endpoint()
    {
        /** Parameters:
              - empty bind address
              - manual_routing callback

        */

        auto e = _q->endpoint(oxen::quic::Address{});
        e->listen(_tls_creds);
        return e;
    }

}  //  namespace llarp
