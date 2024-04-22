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

        void allow_transit();

        void reject_transit();

        bool is_transit_allowed() const;

        bool has_transit_hop(const std::shared_ptr<TransitHop>& hop);

        void put_transit_hop(std::shared_ptr<TransitHop> hop);

        std::shared_ptr<Path> get_path(const std::shared_ptr<TransitHop>& hop);

        std::shared_ptr<Path> get_path_by_pivot(const HopID& path_id);

        std::shared_ptr<Path> get_path_by_pivot(const RouterID& upstream);

        std::shared_ptr<Path> get_path_by_upstream(const HopID& pivot);

        std::shared_ptr<Path> get_path_by_upstream(const RouterID& pivot);

        std::shared_ptr<TransitHop> get_path_for_transfer(const HopID& topath);

        std::shared_ptr<TransitHop> get_transit_hop(const HopID&);

        std::shared_ptr<PathHandler> get_path_handler_by_upstream(const HopID& id);

        std::shared_ptr<PathHandler> get_path_handler_by_pivot(const HopID& id);

        /// get a set of all paths that we own who's endpoint is r
        std::vector<std::shared_ptr<Path>> get_local_paths_to_remote(const RouterID& r);

        void add_path(std::shared_ptr<Path> p);

        void drop_path(const std::shared_ptr<Path>& p);

        void drop_paths(std::vector<std::shared_ptr<Path>> droplist);

      private:
        const RouterID _local_rid;

        using Lock_t = util::NullLock;
        mutable util::NullMutex paths_mutex;

        std::unordered_map<HopID, std::shared_ptr<TransitHop>> _transit_hops;

        // lookup upstream RouterID by upstream {rx,tx}ID
        std::unordered_map<HopID, RouterID> _path_upstream_lookup;

        // maps paths to the RouterID of the upstream (first hop)
        std::unordered_map<RouterID, std::shared_ptr<Path>> _path_upstream_map;

        // map paths to the {rx,tx}id of the pivot
        std::unordered_map<HopID, std::shared_ptr<Path>> _path_pivot_map;

        bool _allow_transit{false};
    };
}  // namespace llarp::path
