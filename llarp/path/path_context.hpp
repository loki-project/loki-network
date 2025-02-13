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
}

namespace llarp::path
{
    struct PathContext
    {
        explicit PathContext(Router& r);

      private:
        Router& _r;

        using Lock_t = util::NullLock;
        mutable util::NullMutex paths_mutex;

        // Paths are 1:1 with edge rxIDs
        std::unordered_map<HopID, std::shared_ptr<Path>> _path_map;

        std::unordered_map<HopID, std::shared_ptr<TransitHop>> _transit_hops;

        bool _allow_transit{false};

        // internal unsafe methods
        void _drop_path(const HopID& hop_id);

        std::shared_ptr<Path> _get_path(const HopID& hop_id) const;

      public:
        std::tuple<size_t, size_t> path_ctx_stats() const;

        bool has_transit_hop(const std::shared_ptr<TransitHop>& hop) const;

        bool has_transit_hop(const HopID& hop_id) const;

        void put_transit_hop(std::shared_ptr<TransitHop> hop);

        bool has_path(const HopID& hop_id) const;

        std::shared_ptr<Path> get_path(const std::shared_ptr<TransitHop>& hop) const;

        std::shared_ptr<Path> get_path(const HopID& hop_id) const;

        std::shared_ptr<TransitHop> get_path_for_transfer(const HopID& topath);

        std::shared_ptr<TransitHop> get_transit_hop(const HopID&) const;

        std::shared_ptr<PathHandler> get_path_handler(const HopID& id);

        void add_path(std::shared_ptr<Path> p);

        void drop_path(const HopID& hop_id);

        void drop_path(const std::shared_ptr<Path>& p);

        void drop_paths(std::vector<HopID> droplist);

        void expire_hops(std::chrono::milliseconds now);

        void allow_transit();

        void reject_transit();

        bool is_transit_allowed() const;
    };
}  // namespace llarp::path
