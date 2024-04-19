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

    std::shared_ptr<QUICTunnel> QUICTunnel::make(Router& r)
    {
        std::shared_ptr<QUICTunnel> q{new QUICTunnel(r)};
        return q;
    }

    std::shared_ptr<oxen::quic::Endpoint> QUICTunnel::startup_endpoint(const std::shared_ptr<path::Path>& path)
    {
        auto e = _q->endpoint(
            oxen::quic::Address{}, oxen::quic::opt::manual_routing{[&](const oxen::quic::Path&, bstring_view data) {
                path->send_path_data_message(std::string{reinterpret_cast<const char*>(data.data()), data.size()});
            }});

        return e;
    }

    uint16_t QUICTunnel::listen()
    {
        return {};
    }

}  //  namespace llarp
