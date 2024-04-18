#pragma once

#include "path_handler.hpp"
#include "path_types.hpp"
#include "transit_hop.hpp"

#include <llarp/ev/loop.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/decaying_hashset.hpp>

#include <memory>
#include <unordered_map>

namespace llarp::path
{
    struct PathContext
    {
        explicit PathContext(RouterID local_rid);

        /// called from router tick function
        void expire_paths(std::chrono::milliseconds now);

        void allow_transit();

        void reject_transit();

        bool is_transit_allowed() const;

        bool has_transit_hop(const std::shared_ptr<TransitHop>& hop);

        void put_transit_hop(std::shared_ptr<TransitHop> hop);

        std::shared_ptr<Path> get_path(const HopID& path_id);

        std::shared_ptr<TransitHop> get_path_for_transfer(const HopID& topath);

        std::shared_ptr<TransitHop> get_transit_hop(const HopID&);

        std::shared_ptr<TransitHop> get_transit_hop(const RouterID&, const HopID&);

        std::shared_ptr<PathHandler> get_path_handler(const HopID& id);

        /// get a set of all paths that we own who's endpoint is r
        std::vector<std::shared_ptr<Path>> get_local_paths_to_remote(const RouterID& r);

        void add_path(std::shared_ptr<Path> p);

      private:
        const RouterID _local_rid;

        std::unordered_map<HopID, std::shared_ptr<TransitHop>> _transit_hops;

        std::unordered_map<HopID, std::shared_ptr<Path>> _local_paths;

        bool _allow_transit{false};
    };
}  // namespace llarp::path
