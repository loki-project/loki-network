#pragma once
#include "policy.hpp"

#include <llarp/handlers/exit.hpp>

#include <string>
#include <unordered_map>

namespace llarp::exit
{
    /// owner of all the exit endpoints
    struct Context
    {
        Context(Router* r);
        ~Context();

        void Tick(llarp_time_t now);

        void clear_all_endpoints();

        util::StatusObject ExtractStatus() const;

        /// send close to all exit sessions and remove all sessions
        void stop();

        void add_exit_endpoint(const std::string& name, const NetworkConfig& networkConfig, const DnsConfig& dnsConfig);

        bool obtain_new_exit(const PubKey& remote, const PathID_t& path, bool permitInternet);

        exit::Endpoint* find_endpoint_for_path(const PathID_t& path) const;

        /// calculate (pk, tx, rx) for all exit traffic
        using TrafficStats = std::unordered_map<PubKey, std::pair<uint64_t, uint64_t>>;

        void calculate_exit_traffic(TrafficStats& stats);

        std::shared_ptr<handlers::ExitEndpoint> get_exit_endpoint(std::string name) const;

      private:
        Router* router;
        std::unordered_map<std::string, std::shared_ptr<handlers::ExitEndpoint>> _exits;
        std::list<std::shared_ptr<handlers::ExitEndpoint>> _closed;
    };
}  // namespace llarp::exit
