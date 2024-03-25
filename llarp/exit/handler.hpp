#pragma once

// #include <llarp/dns/server.hpp>
#include <llarp/endpoint_base.hpp>
#include <llarp/handlers/remote.hpp>
#include <llarp/session/session.hpp>

#include <string>
#include <unordered_map>

namespace llarp::exit
{
    /** This class is the counterpart to service::Handler. While service::Handler manages sessions
        to remote hidden services, exit::Handler manages sessions to remote exit nodes
    */
    struct Handler final : /* public handlers::RemoteHandler, */ public std::enable_shared_from_this<Handler>
    {
      private:
        void _configure();

      public:
        Handler(std::string name, Router& r);
        ~Handler() = default;
    };
}  // namespace llarp::exit
