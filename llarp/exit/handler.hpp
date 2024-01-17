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
    struct Handler final : public handlers::RemoteHandler, public std::enable_shared_from_this<Handler>
    {
        Handler(std::string name, Router& r);
        ~Handler() override = default;

        std::shared_ptr<PathHandler> get_self() override
        {
            return shared_from_this();
        }

        std::weak_ptr<PathHandler> get_weak() override
        {
            return weak_from_this();
        }
    };
}  // namespace llarp::exit
