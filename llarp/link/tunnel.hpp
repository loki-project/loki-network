#pragma once

#include <llarp/ev/tcp.hpp>
#include <llarp/util/time.hpp>

namespace llarp
{
    inline const auto LOCALHOST = "127.0.0.1"s;
    inline const auto TUNNEL_SEED = oxenc::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
    inline const auto TUNNEL_PUBKEY =
        oxenc::from_hex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

    namespace path
    {
        struct Path;
    }

    struct Router;

    class QUICTunnel
    {
      public:
        static std::shared_ptr<QUICTunnel> make(Router& r);

      private:
        QUICTunnel(Router& r);

        Router& _router;

        // NOTE: DO NOT CHANGE THE ORDER OF THESE TWO OBJECTS
        std::unique_ptr<oxen::quic::Network> _q;  // constructed using the lokinet event loop
        std::shared_ptr<oxen::quic::GNUTLSCreds> _tls_creds;

      public:
        // Invoked in session initiation to produce Endpoint that lives in {Inbound,Outbound}Session objects
        std::shared_ptr<oxen::quic::Endpoint> startup_endpoint(const std::shared_ptr<path::Path>& p);

        const std::shared_ptr<oxen::quic::GNUTLSCreds>& creds()
        {
            return _tls_creds;
        }

        uint16_t listen();

        //
    };

}  //  namespace llarp
