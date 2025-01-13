#include "tunnel.hpp"

#include <llarp/router/router.hpp>

#include <oxenc/hex.h>

namespace llarp
{
    QUICTunnel::QUICTunnel(Router& r)
        : _router{r},
          _q{std::make_unique<oxen::quic::Network>(_router.loop()->_loop)},
          _tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_keys(TUNNEL_SEED, TUNNEL_PUBKEY)}
    {}

    std::shared_ptr<QUICTunnel> QUICTunnel::make(Router& r) { return r.loop()->template make_shared<QUICTunnel>(r); }

    uint16_t QUICTunnel::listen() { return {}; }

}  //  namespace llarp
