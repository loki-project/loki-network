#pragma once

#include <llarp/address/ip_range.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/endpoint_base.hpp>
#include <llarp/path/abstracthophandler.hpp>
#include <llarp/service/types.hpp>
#include <llarp/util/time.hpp>

#include <queue>

namespace llarp::exit
{
    /** This class is the counterpart to service::Endpoint. While service::Endpoint manages hidden
        services ran locally, exit::Endpoint manages locally operated client exit nodes
    */
    struct Endpoint /* final */ : public path::PathHandler,
                                  public EndpointBase,
                                  public std::enable_shared_from_this<Endpoint>
    {
        std::shared_ptr<path::PathHandler> get_self() override
        {
            return shared_from_this();
        }

        std::weak_ptr<path::PathHandler> get_weak() override
        {
            return weak_from_this();
        }

        std::unordered_map<IPRange, service::Address> _exit_map;
        std::set<IPRange> _owned_ranges;
    };
}  // namespace llarp::exit
