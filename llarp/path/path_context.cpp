#include "path_context.hpp"

#include "path.hpp"

#include <llarp/router/router.hpp>

namespace llarp::path
{
    static auto logcat = log::Cat("pathctx");

    PathContext::PathContext(Router& r) : _r{r} {}

    void PathContext::allow_transit()
    {
        _allow_transit = true;
    }

    bool PathContext::is_transit_allowed() const
    {
        return _allow_transit;
    }

    void PathContext::add_path(std::shared_ptr<Path> path)
    {
        _path_map.emplace(path->upstream_rxid(), path);
        _path_map.emplace(path->pivot_txid(), path);
    }

    void PathContext::drop_paths(std::vector<HopID> droplist)
    {
        for (auto itr = droplist.begin(); itr != droplist.end();)
        {
            _drop_path(*itr);
            itr = droplist.erase(itr);
        }
    }

    void PathContext::expire_hops(std::chrono::milliseconds now)
    {
        size_t n = 0;

        for (auto itr = _transit_hops.begin(); itr != _transit_hops.end();)
        {
            if (itr->second->is_expired(now))
            {
                itr = _transit_hops.erase(itr);
                n += 1;
            }
            else
                ++itr;
        }

        if (n)
            log::info(logcat, "{} expired TransitHops purged!", n);
    }

    void PathContext::drop_path(const HopID& hop_id)
    {
        _r.loop()->call([&]() { _drop_path(hop_id); });
    }

    void PathContext::drop_path(const std::shared_ptr<Path>& path)
    {
        _drop_path(path->upstream_rxid());
        _drop_path(path->pivot_txid());
    }

    std::tuple<size_t, size_t> PathContext::path_ctx_stats() const
    {
        return _r.loop()->call_get([&]() -> std::tuple<size_t, size_t> {
            return {_path_map.size() / 2, _transit_hops.size() / 2};
        });
    }

    bool PathContext::has_transit_hop(const std::shared_ptr<TransitHop>& hop) const
    {
        assert(_r.loop()->in_event_loop());
        return has_transit_hop(hop->rxid()) or has_transit_hop(hop->txid());
    }

    bool PathContext::has_transit_hop(const HopID& hop_id) const
    {
        assert(_r.loop()->in_event_loop());
        return _transit_hops.count(hop_id);
    }

    void PathContext::put_transit_hop(std::shared_ptr<TransitHop> hop)
    {
        assert(_r.loop()->in_event_loop());
        _transit_hops.emplace(hop->rxid(), hop);
        _transit_hops.emplace(hop->txid(), hop);
    }

    std::shared_ptr<TransitHop> PathContext::get_transit_hop(const HopID& path_id) const
    {
        assert(_r.loop()->in_event_loop());
        if (auto itr = _transit_hops.find(path_id); itr != _transit_hops.end())
            return itr->second;

        return nullptr;
    }

    void PathContext::_drop_path(const HopID& hop_id)
    {
        assert(_r.loop()->in_event_loop());

        if (auto itr = _path_map.find(hop_id); itr != _path_map.end())
            _path_map.erase(itr);
    }

    std::shared_ptr<Path> PathContext::_get_path(const HopID& hop_id) const
    {
        assert(_r.loop()->in_event_loop());

        if (auto itr = _path_map.find(hop_id); itr != _path_map.end())
            return itr->second;

        return nullptr;
    }

    std::shared_ptr<Path> PathContext::get_path(const HopID& hop_id) const
    {
        assert(_r.loop()->in_event_loop());
        return _get_path(hop_id);
    }

    bool PathContext::has_path(const HopID& hop_id) const
    {
        assert(_r.loop()->in_event_loop());
        return _path_map.contains(hop_id);
    }

    std::shared_ptr<Path> PathContext::get_path(const std::shared_ptr<TransitHop>& hop) const
    {
        assert(_r.loop()->in_event_loop());
        if (auto maybe_path = _get_path(hop->rxid()))
            return maybe_path;

        if (auto maybe_path = _get_path(hop->txid()))
            return maybe_path;

        return nullptr;
    }

    std::shared_ptr<PathHandler> PathContext::get_path_handler(const HopID& id)
    {
        return _r.loop()->call_get([&]() -> std::shared_ptr<PathHandler> {
            if (auto maybe_path = _get_path(id))
                return maybe_path->get_parent();

            return nullptr;
        });
    }

    std::shared_ptr<TransitHop> PathContext::get_path_for_transfer(const HopID& id)
    {
        return _r.loop()->call_get([&]() -> std::shared_ptr<TransitHop> {
            if (auto itr = _transit_hops.find(id); itr != _transit_hops.end())
                return itr->second;

            return nullptr;
        });
    }

}  // namespace llarp::path
