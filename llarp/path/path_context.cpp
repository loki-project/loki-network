#include "path_context.hpp"

#include "path.hpp"

#include <llarp/router/router.hpp>

namespace llarp::path
{
    PathContext::PathContext(RouterID local_rid) : _local_rid{std::move(local_rid)} {}

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
        Lock_t l{paths_mutex};

        std::vector<std::shared_ptr<Path>> found;

        for (const auto& [pathid, path] : _path_map)
        {
            if (path->upstream_txid() == pathid)
                continue;

            if (path->pivot_rid() == r && path->is_ready())
                found.push_back(path);
        }
        return found;
    }

    void PathContext::add_path(std::shared_ptr<Path> path)
    {
        Lock_t l{paths_mutex};

        _path_map.emplace(path->upstream_rxid(), path);
        _path_map.emplace(path->upstream_txid(), path);

        _path_map.emplace(path->pivot_rxid(), path);
        _path_map.emplace(path->pivot_txid(), path);
    }

    void PathContext::drop_paths(std::vector<std::shared_ptr<Path>> droplist)
    {
        Lock_t l{paths_mutex};

        for (auto itr = droplist.begin(); itr != droplist.end();)
        {
            drop_path(*itr);
            itr = droplist.erase(itr);
        }
    }

    intro_set PathContext::get_recent_ccs() const
    {
        Lock_t l{paths_mutex};

        intro_set intros;
        auto now = llarp::time_now_ms();

        for (auto& [_, p] : _path_map)
        {
            if (p->is_ready() and not p->intro.is_expired(now))
                intros.emplace(p->intro);
        }

        return intros;
    }

    void PathContext::drop_path(const std::shared_ptr<Path>& path)
    {
        Lock_t l{paths_mutex};

        if (auto itr = _path_map.find(path->upstream_rxid()); itr != _path_map.end())
            _path_map.erase(itr);

        if (auto itr = _path_map.find(path->upstream_txid()); itr != _path_map.end())
            _path_map.erase(itr);

        if (auto itr = _path_map.find(path->pivot_rxid()); itr != _path_map.end())
            _path_map.erase(itr);

        if (auto itr = _path_map.find(path->pivot_txid()); itr != _path_map.end())
            _path_map.erase(itr);
    }

    bool PathContext::has_transit_hop(const std::shared_ptr<TransitHop>& hop)
    {
        Lock_t l{paths_mutex};

        return _transit_hops.count(hop->rxid()) or _transit_hops.count(hop->txid());
    }

    void PathContext::put_transit_hop(std::shared_ptr<TransitHop> hop)
    {
        Lock_t l{paths_mutex};

        _transit_hops.emplace(hop->rxid(), hop);
        _transit_hops.emplace(hop->txid(), hop);
    }

    std::shared_ptr<TransitHop> PathContext::get_transit_hop(const HopID& path_id)
    {
        Lock_t l{paths_mutex};

        if (auto itr = _transit_hops.find(path_id); itr != _transit_hops.end())
            return itr->second;

        return nullptr;
    }

    std::shared_ptr<Path> PathContext::get_path(const HopID& hop_id)
    {
        Lock_t l{paths_mutex};

        if (auto itr = _path_map.find(hop_id); itr != _path_map.end())
            return itr->second;

        return nullptr;
    }

    std::shared_ptr<Path> PathContext::get_path(const std::shared_ptr<TransitHop>& hop)
    {
        Lock_t l{paths_mutex};

        if (auto maybe_path = get_path(hop->rxid()); maybe_path)
            return maybe_path;

        if (auto maybe_path = get_path(hop->txid()); maybe_path)
            return maybe_path;

        return nullptr;
    }

    std::shared_ptr<PathHandler> PathContext::get_path_handler(const HopID& id)
    {
        Lock_t l{paths_mutex};

        if (auto maybe_path = get_path(id); maybe_path)
        {
            if (auto parent = maybe_path->handler.lock())
                return parent;
        }

        return nullptr;
    }

    std::shared_ptr<TransitHop> PathContext::get_path_for_transfer(const HopID& id)
    {
        Lock_t l{paths_mutex};

        if (auto itr = _transit_hops.find(id); itr != _transit_hops.end())
            return itr->second;

        return nullptr;
    }

}  // namespace llarp::path
