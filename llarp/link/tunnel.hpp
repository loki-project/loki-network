#pragma once

#include <llarp/ev/tcp.hpp>
#include <llarp/util/time.hpp>

#include <oxenc/hex.h>

namespace llarp
{
    using namespace oxenc::literals;

    const auto LOCALHOST = "127.0.0.1"s;

    inline constexpr auto TUNNEL_SEED = "0000000000000000000000000000000000000000000000000000000000000000"_hex;

    inline constexpr auto TUNNEL_PUBKEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"_hex;

    const auto LOCALHOST_BLANK = oxen::quic::Address{LOCALHOST, 0};

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
        const std::unique_ptr<oxen::quic::Network>& net() { return _q; }

        const std::shared_ptr<oxen::quic::GNUTLSCreds>& creds() { return _tls_creds; }

        uint16_t listen();

        //
    };

}  //  namespace llarp
