#pragma once

#include "endpoint.hpp"

#include <llarp/config/config.hpp>
#include <llarp/handlers/tun.hpp>
#include <llarp/net/net.hpp>

#include <unordered_map>

/*
  TODO:
    - if we are only using one local endpoint, does this need to change to account for that?
*/

namespace llarp::service
{
    /// holds all the hidden service endpoints we own
    /// this should be refactored (removed entirely...?) now that lokinet
    ///       only supports one endpoint per instance
    struct Context
    {
        explicit Context(Router* r);
        ~Context();

        void Tick(llarp_time_t now);

        /// stop all held services
        bool StopAll();

        StatusObject ExtractStatus() const;

        bool hasEndpoints();

        /// function visitor returns false to prematurely break iteration
        void ForEachService(std::function<bool(const std::string&, const std::shared_ptr<Endpoint>&)> visit) const;

        /// add endpoint via config
        void AddEndpoint(const Config& conf, bool autostart = false);

        /// inject endpoint instance
        void InjectEndpoint(std::string name, std::shared_ptr<Endpoint> ep);

        /// stop and remove an endpoint by name
        /// return false if we don't have the hidden service with that name
        bool RemoveEndpoint(const std::string& name);

        std::shared_ptr<Endpoint> GetEndpointByName(const std::string& name) const;

        std::shared_ptr<Endpoint> GetDefault() const
        {
            return GetEndpointByName("default");
        }

        bool StartAll();

       private:
        Router* const m_Router;
        std::unordered_map<std::string, std::shared_ptr<Endpoint>> m_Endpoints;
        std::list<std::shared_ptr<Endpoint>> m_Stopped;
    };
}  // namespace llarp::service
