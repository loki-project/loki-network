#pragma once

#include "path_handler.hpp"
#include "path_types.hpp"
#include "transit_hop.hpp"

#include <llarp/contact/client_contact.hpp>
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

        std::shared_ptr<Path> get_path(const HopID& hop_id);

        std::shared_ptr<TransitHop> get_path_for_transfer(const HopID& topath);

        std::shared_ptr<TransitHop> get_transit_hop(const HopID&);

        std::shared_ptr<PathHandler> get_path_handler(const HopID& id);

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

        /** TODO:
            - paths are not 1:1 with upstream RID
            - paths are 1:1 with txid's
        */

        std::unordered_map<HopID, std::shared_ptr<Path>> _path_map;

        bool _allow_transit{false};
    };
}  // namespace llarp::path
