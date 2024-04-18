#pragma once

#include <llarp/ev/tcp.hpp>
#include <llarp/util/time.hpp>

namespace llarp
{
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

        std::unordered_map<uint16_t, std::shared_ptr<TCPHandle>> _binds;

        // Invoked in session initiation to produce Endpoint that lives in {Inbound,Outbound}Session objects
        std::shared_ptr<oxen::quic::Endpoint> startup_endpoint();

      public:
        uint16_t listen(tcpsock_hook tcp_maker);

        //
    };

}  //  namespace llarp
