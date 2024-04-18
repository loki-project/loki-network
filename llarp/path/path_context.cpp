#include "path_context.hpp"

#include "path.hpp"

#include <llarp/router/router.hpp>

namespace llarp::path
{
    PathContext::PathContext(RouterID local_rid) : _local_rid{std::move(local_rid)}
    {}

    void PathContext::allow_transit()
    {
        _allow_transit = true;
    }

    bool PathContext::is_transit_allowed() const
    {
        return _allow_transit;
    }

    std::vector<std::shared_ptr<Path>> PathContext::get_local_paths_to_remote(const RouterID& r)
    {
        std::vector<std::shared_ptr<Path>> found;
        for (const auto& [pathid, path] : _local_paths)
        {
            // each path is stored in this map twice, once for each pathid at the first hop
            // This will make the output deduplicated without needing a std::set
            // TODO: we should only need to map one pathid; as the path owner we only send/receive
            //       packets with the first hop's RXID; its TXID is for packets between it and
            //       hop 2.
            // TODO: Also, perhaps we want a bit of data duplication here, e.g. a map from
            //       RouterID (terminal hop) to shared_ptr<Path>.
            if (path->upstream_txid() == pathid)
                continue;

            if (path->pivot_router_id() == r && path->IsReady())
                found.push_back(path);
        }
        return found;
    }

    void PathContext::add_path(std::shared_ptr<Path> path)
    {
        _local_paths[path->upstream_txid()] = path;
        _local_paths[path->upstream_rxid()] = path;
    }

    bool PathContext::has_transit_hop(const std::shared_ptr<TransitHop>& hop)
    {
        return _transit_hops.count(hop->rxID()) or _transit_hops.count(hop->txID());
    }

    void PathContext::put_transit_hop(std::shared_ptr<TransitHop> hop)
    {
        _transit_hops.emplace(hop->rxID(), hop);
        _transit_hops.emplace(hop->txID(), hop);
    }

    std::shared_ptr<TransitHop> PathContext::get_transit_hop(const HopID& path_id)
    {
        if (auto itr = _transit_hops.find(path_id); itr != _transit_hops.end())
            return itr->second;

        return nullptr;
    }

    std::shared_ptr<TransitHop> PathContext::get_transit_hop(const RouterID&, const HopID&)
    {
        // if (auto itr = transit_hops.find({rid, path_id}); itr != transit_hops.end())
        //     return itr->second;

        return nullptr;
    }

    std::shared_ptr<Path> PathContext::get_path(const HopID& path_id)
    {
        if (auto itr = _local_paths.find(path_id); itr != _local_paths.end())
            return itr->second;

        return nullptr;
    }

    std::shared_ptr<PathHandler> PathContext::get_path_handler(const HopID& id)
    {
        if (auto itr = _local_paths.find(id); itr != _local_paths.end())
        {
            if (auto parent = itr->second->handler.lock())
                return parent;
        }
        return nullptr;
    }

    std::shared_ptr<TransitHop> PathContext::get_path_for_transfer(const HopID& id)
    {
        if (auto itr = _transit_hops.find(id); itr != _transit_hops.end())
            return itr->second;

        return nullptr;
    }

    void PathContext::expire_paths(std::chrono::milliseconds now)
    {
        for (auto itr = _transit_hops.begin(); itr != _transit_hops.end();)
        {
            if (itr->second->is_expired(now))
                itr = _transit_hops.erase(itr);
            else
                ++itr;
        }

        for (auto itr = _local_paths.begin(); itr != _local_paths.end();)
        {
            if (itr->second->is_expired(now))
                itr = _local_paths.erase(itr);
            else
                ++itr;
        }
    }
}  // namespace llarp::path
