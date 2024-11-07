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

namespace llarp
{
    struct Router;

    namespace path
    {
        struct PathContext
        {
            explicit PathContext(Router& r);

            void allow_transit();

            void reject_transit();

            bool is_transit_allowed() const;

            bool has_transit_hop(const std::shared_ptr<TransitHop>& hop) const;

            void put_transit_hop(std::shared_ptr<TransitHop> hop);

            std::shared_ptr<Path> get_path(const std::shared_ptr<TransitHop>& hop) const;

            std::shared_ptr<Path> get_path(const HopID& hop_id) const;

            std::shared_ptr<TransitHop> get_path_for_transfer(const HopID& topath);

            std::shared_ptr<TransitHop> get_transit_hop(const HopID&) const;

            std::shared_ptr<PathHandler> get_path_handler(const HopID& id);

            void add_path(std::shared_ptr<Path> p);

            void drop_path(const HopID& hop_id);

            void drop_path(const std::shared_ptr<Path>& p);

            void drop_paths(std::vector<std::shared_ptr<Path>> droplist);

            void expire_hops(std::chrono::milliseconds now);

          private:
            Router& _r;

            using Lock_t = util::NullLock;
            mutable util::NullMutex paths_mutex;

            std::unordered_map<HopID, std::shared_ptr<TransitHop>> _transit_hops;

            /** TODO:
                - paths are not 1:1 with upstream RID
                - paths are 1:1 with edge rxIDs
            */

            std::unordered_map<HopID, std::shared_ptr<Path>> _path_map;

            bool _allow_transit{false};
        };
    }  // namespace path
}  // namespace llarp
