#include "path_handler.hpp"

#include "path.hpp"
#include "path_context.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/link/link_manager.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/profiling.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging.hpp>

#include <functional>

namespace llarp::path
{
    static auto logcat = log::Cat("pathhandler");

    bool BuildLimiter::Attempt(const RouterID& router)
    {
        return _edge_limiter.Insert(router);
    }

    void BuildLimiter::Decay(std::chrono::milliseconds now)
    {
        _edge_limiter.Decay(now);
    }

    bool BuildLimiter::Limited(const RouterID& router) const
    {
        return _edge_limiter.Contains(router);
    }

    StatusObject BuildStats::ExtractStatus() const
    {
        return StatusObject{
            {"success", success}, {"attempts", attempts}, {"timeouts", timeouts}, {"fails", build_fails}};
    }

    std::string BuildStats::to_string() const
    {
        return fmt::format(
            "{:.2f} percent success (success={} attempts={} timeouts={} fails={})",
            SuccessRatio() * 100.0,
            success,
            attempts,
            timeouts,
            build_fails);
    }

    double BuildStats::SuccessRatio() const
    {
        if (attempts)
            return double(success) / double(attempts);
        return 0.0;
    }

    PathHandler::PathHandler(Router& _r, size_t num_paths, size_t _n_hops)
        : _running{true}, num_paths_desired{num_paths}, _router{_r}, num_hops{_n_hops}
    {}

    void PathHandler::add_path(std::shared_ptr<Path> p)
    {
        return add_path(p->pivot_router_id(), p);
    }

    void PathHandler::add_path(const RouterID& remote, std::shared_ptr<Path> path)
    {
        Lock_t l(paths_mutex);

        _paths.insert_or_assign(remote, path);
        associate_hop_ids(path);
    }

    std::optional<std::shared_ptr<Path>> PathHandler::get_random_path()
    {
        std::optional<std::pair<RouterID, std::shared_ptr<path::Path>>> t = std::nullopt;

        std::sample(_paths.begin(), _paths.end(), &t, 1, csrng);

        return t.has_value() ? std::make_optional(t->second) : std::nullopt;
    }

    std::optional<std::shared_ptr<Path>> PathHandler::get_path_conditional(
        std::function<bool(std::shared_ptr<Path>)> filter)
    {
        std::optional<std::shared_ptr<Path>> rand = std::nullopt;

        if (rand and filter(*rand))
            return rand;

        size_t i = 0;

        for (const auto& p : _paths)
        {
            if (not filter(p.second))
                continue;

            if (++i <= 1)
            {
                rand = p.second;
                continue;
            }

            size_t x = csrng() % (i + 1);
            if (x <= 1)
                rand = p.second;
        }

        return rand;
    }

    std::optional<std::unordered_set<std::shared_ptr<Path>>> PathHandler::get_n_random_paths(size_t n, bool exact)
    {
        Lock_t l{paths_mutex};

        auto selected = std::make_optional<std::unordered_set<std::shared_ptr<path::Path>>>();
        selected->reserve(n);

        for (size_t i = 0; i < n; ++i)
        {
            std::pair<RouterID, std::shared_ptr<path::Path>> t;

            std::sample(_paths.begin(), _paths.end(), &t, 1, csrng);

            selected->insert(selected->end(), t.second);
        }

        if (selected->size() < (exact ? n : 1))
            selected.reset();

        return selected;
    }

    std::optional<std::vector<std::shared_ptr<Path>>> PathHandler::get_n_random_paths_conditional(
        size_t n, std::function<bool(std::shared_ptr<Path>)> filter, bool exact)
    {
        Lock_t l{paths_mutex};

        auto selected = std::make_optional<std::vector<std::shared_ptr<path::Path>>>();
        selected->reserve(n);

        size_t i = 0;

        for (const auto& p : _paths)
        {
            // ignore any RC's that do not pass the condition
            if (not filter(p.second))
                continue;

            // load the first n RC's that pass the condition into selected
            if (++i <= n)
            {
                selected->push_back(p.second);
                continue;
            }

            // replace selections with decreasing probability per iteration
            size_t x = csrng() % (i + 1);
            if (x < n)
                (*selected)[x] = p.second;
        }

        if (selected->size() < (exact ? n : 1))
            selected.reset();

        return selected;
    }

    size_t PathHandler::paths_at_time(std::chrono::milliseconds futureTime) const
    {
        size_t num = 0;
        Lock_t l(paths_mutex);

        for (const auto& item : _paths)
        {
            if (item.second->IsReady() && !item.second->is_expired(futureTime))
                ++num;
        }
        return num;
    }

    void PathHandler::reset_path_state()
    {
        build_interval_limit = PATH_BUILD_RATE;
        _last_build = 0s;
    }

    // called within the scope of locked mutex
    void PathHandler::tick_paths()
    {
        const auto now = llarp::time_now_ms();

        for (auto& item : _paths)
        {
            item.second->Tick(now, &_router);
        }
    }

    std::chrono::milliseconds PathHandler::now() const
    {
        return _router.now();
    }

    // called within the scope of locked mutex
    void PathHandler::expire_paths(std::chrono::milliseconds now)
    {
        if (_paths.size() == 0)
            return;

        for (auto itr = _paths.begin(); itr != _paths.end();)
        {
            if (itr->second->is_expired(now))
            {
                // TODO: this
                HopID txid = itr->second->TXID();
                // router->outboundMessageHandler().RemovePath(std::move(txid));
                HopID rxid = itr->second->RXID();
                // router->outboundMessageHandler().RemovePath(std::move(rxid));
                itr = _paths.erase(itr);
            }
            else
                ++itr;
        }
    }

    // called within the scope of locked mutex
    std::optional<std::shared_ptr<Path>> PathHandler::get_path(HopID hid) const
    {
        if (auto itr = _path_lookup.find(hid); itr != _path_lookup.end())
            return get_path(itr->second);

        return std::nullopt;
    }

    // called within the scope of locked mutex
    std::optional<std::shared_ptr<Path>> PathHandler::get_path(const RouterID& rid) const
    {
        if (auto itr = _paths.find(rid); itr != _paths.end())
            return itr->second;

        return std::nullopt;
    }

    void PathHandler::for_each_path(std::function<void(const std::shared_ptr<Path>&)> visit) const
    {
        Lock_t lock{paths_mutex};

        for (const auto& p : _paths)
        {
            visit(p.second);
        }
    }

    std::optional<std::set<service::Introduction>> PathHandler::get_path_intros_conditional(
        std::function<bool(const service::Introduction&)> filter) const
    {
        std::set<service::Introduction> intros;
        Lock_t l{paths_mutex};

        for (const auto& p : _paths)
        {
            if (p.second->IsReady() and filter(p.second->intro))
            {
                intros.insert(p.second->intro);
            }
        }

        if (intros.empty())
            return std::nullopt;

        return intros;
    }

    void PathHandler::Tick(std::chrono::milliseconds now)
    {
        Lock_t l{paths_mutex};
        std::unordered_set<RouterID> endpoints;

        for (auto& item : _paths)
        {
            endpoints.emplace(item.second->pivot_router_id());
        }

        path_cache.clear();

        for (const auto& ep : endpoints)
        {
            if (auto path = get_path(ep))
            {
                auto p = *path;
                path_cache[ep] = p->get_weak();
            }
        }

        now = llarp::time_now_ms();
        _router.pathbuild_limiter().Decay(now);

        expire_paths(now);

        if (should_build_more())
            build_more();

        tick_paths();

        if (_build_stats.attempts > 50)
        {
            if (_build_stats.SuccessRatio() <= BuildStats::MinGoodRatio && now - last_warn_time > 5s)
            {
                log::warning(logcat, "{} has a low path build success: {}", name(), _build_stats);
                last_warn_time = now;
            }
        }
    }

    StatusObject PathHandler::ExtractStatus() const
    {
        StatusObject obj{
            {"buildStats", _build_stats.ExtractStatus()},
            {"numHops", uint64_t{num_hops}},
            {"numPaths", uint64_t{num_paths_desired}}};
        std::transform(
            _paths.begin(), _paths.end(), std::back_inserter(obj["paths"]), [](const auto& item) -> StatusObject {
                return item.second->ExtractStatus();
            });
        return obj;
    }

    std::optional<RemoteRC> PathHandler::select_first_hop(const std::set<RouterID>& exclude) const
    {
        std::optional<RemoteRC> found = std::nullopt;
        _router.for_each_connection([&](link::Connection& conn) {
            RouterID rid{conn.conn->remote_key()};

#ifndef TESTNET
            if (_router.is_bootstrap_node(rid))
                return;
#endif
            if (exclude.count(rid))
                return;

            if (build_cooldown_hit(rid))
                return;

            if (_router.router_profiling().is_bad_for_path(rid))
                return;

            found = _router.node_db()->get_rc(rid);
        });
        return found;
    }

    size_t PathHandler::num_paths() const
    {
        Lock_t l(paths_mutex);

        return _paths.size();
    }

    bool PathHandler::stop(bool)
    {
        _running = false;

        Lock_t l{paths_mutex};

        for (auto itr = _paths.begin(); itr != _paths.end();)
        {
            auto& p = itr->second;
            dissociate_hop_ids(p);
            itr = _paths.erase(itr);
        }

        return true;
    }

    bool PathHandler::is_stopped() const
    {
        return !_running.load();
    }

    bool PathHandler::should_remove() const
    {
        return is_stopped() and num_paths() == 0;
    }

    bool PathHandler::build_cooldown_hit(RouterID edge) const
    {
        return _router.pathbuild_limiter().Limited(edge);
    }

    bool PathHandler::build_cooldown() const
    {
        return llarp::time_now_ms() < _last_build + build_interval_limit;
    }

    bool PathHandler::should_build_more() const
    {
        if (is_stopped())
            return false;

        if (build_cooldown())
            return false;

        return num_paths() < num_paths_desired;
    }

    std::optional<std::vector<RemoteRC>> PathHandler::get_hops_to_random()
    {
        auto filter = [&r = _router](const RemoteRC& rc) -> bool {
            return not r.router_profiling().is_bad_for_path(rc.router_id(), 1);
        };

        if (auto maybe = _router.node_db()->get_random_rc_conditional(filter))
            return aligned_hops_to_remote(maybe->router_id());

        return std::nullopt;
    }

    std::optional<std::vector<RemoteRC>> PathHandler::aligned_hops_to_remote(
        const RouterID& pivot, const std::set<RouterID>& exclude)
    {
        const auto& path_config = _router.config()->paths;

        // make a copy here to reference rather than creating one in the lambda every iteration
        std::set<RouterID> to_exclude{exclude.begin(), exclude.end()};
        std::vector<RemoteRC> hops;

        if (auto maybe = select_first_hop(exclude))
            hops.push_back(*maybe);
        else
        {
            log::warning(logcat, "{} has no first hop candidate", name());
            return std::nullopt;
        }

        RemoteRC remote_rc;
        to_exclude.insert(remote_rc.router_id());  // we will manually add this last

        if (const auto maybe = _router.node_db()->get_rc(pivot))
        {
            remote_rc = *maybe;
        }
        else
            return std::nullopt;

        // leave one extra spot for the terminal node
        auto hops_needed = num_hops - hops.size() - 1;

        auto filter = [&r = _router, &to_exclude](const RemoteRC& rc) -> bool {
            const auto& rid = rc.router_id();

            if (r.router_profiling().is_bad_for_path(rid, 1))
                to_exclude.insert(rid);

            if (to_exclude.count(rid))
                return false;

            // add the rid on a success case so we don't select it again
            to_exclude.insert(rid);

            return true;
        };

        auto maybe_rcs = _router.node_db()->get_n_random_rcs_conditional(hops_needed, filter, true);

        if (maybe_rcs)
        {
            auto& rcs = *maybe_rcs;
            hops.insert(hops.end(), rcs.begin(), rcs.end());
            hops.emplace_back(remote_rc);

#ifndef TESTNET
            if (not path_config.check_rcs({hops.begin(), hops.end()}))
                return std::nullopt;
#endif

            return hops;
        }

        return std::nullopt;
    }

    bool PathHandler::build_path_to_random()
    {
        if (auto maybe_hops = get_hops_to_random())
        {
            log::debug(logcat, "{} building path to random remote", name());
            build(*maybe_hops);
            return true;
        }

        log::warning(logcat, "{} failed to get hops for path-build to random", name());
        return false;
    }

    bool PathHandler::build_path_aligned_to_remote(const RouterID& remote)
    {
        if (auto maybe_hops = aligned_hops_to_remote(remote))
        {
            log::debug(logcat, "{} building path to {}", name(), remote);
            build(*maybe_hops);
            return true;
        }

        log::warning(logcat, "{} failed to get hops for path-build to {}", name(), remote);
        return false;
    }

    std::shared_ptr<Path> PathHandler::build1(std::vector<RemoteRC>& hops)
    {
        if (is_stopped())
        {
            log::info(logcat, "Path builder is stopped, aborting path build...");
            return nullptr;
        }

        _last_build = llarp::time_now_ms();
        const auto& edge = hops[0].router_id();
        const auto& terminus = hops.back().router_id();

        if (not _router.pathbuild_limiter().Attempt(edge))
        {
            log::warning(logcat, "{} building too quickly to edge router {}", name(), edge);
            return nullptr;
        }

        {
            Lock_t l{paths_mutex};

            if (auto [it, b] = _paths.try_emplace(terminus, nullptr); not b)
            {
                log::error(logcat, "Pending build to {} already underway... aborting...", terminus);
                return nullptr;
            }
        }

        auto path = std::make_shared<path::Path>(_router, hops, get_weak());

        log::info(logcat, "{} building path -> {} : {}", name(), path->to_string(), path->HopsString());

        return path;
    }

    std::string PathHandler::build2(std::shared_ptr<Path>& path)
    {
        oxenc::bt_list_producer frames;
        std::vector<std::string> frame_str(path::MAX_LEN);
        auto& path_hops = path->hops;
        size_t n_hops = path_hops.size();
        size_t last_len{0};

        // each hop will be able to read the outer part of its frame and decrypt
        // the inner part with that information.  It will then do an onion step on the
        // remaining frames so the next hop can read the outer part of its frame,
        // and so on.  As this de-onion happens from hop 1 to n, we create and onion
        // the frames from hop n downto 1 (i.e. reverse order).  The first frame is
        // not onioned.
        //
        // Onion-ing the frames in this way will prevent relays controlled by
        // the same entity from knowing they are part of the same path
        // (unless they're adjacent in the path; nothing we can do about that obviously).

        // i from n_hops downto 0
        size_t i = n_hops;

        while (i > 0)
        {
            i--;
            bool lastHop = (i == (n_hops - 1));

            const auto& next_hop = lastHop ? path_hops[i].rc.router_id() : path_hops[i + 1].rc.router_id();

            frame_str[i] = PathBuildMessage::serialize_hop(path_hops[i], next_hop);

            // all frames should be the same length...not sure what that is yet
            // it may vary if path lifetime is non-default, as that is encoded as an
            // integer in decimal, but it should be constant for a given path
            if (last_len != 0)
                assert(frame_str[i].size() == last_len);

            last_len = frame_str[i].size();

            // onion each previously-created frame using the established shared secret and
            // onion_nonce = path_hops[i].nonce ^ path_hops[i].nonceXOR, which the transit hop
            // will have recovered after decrypting its frame.
            // Note: final value passed to crypto::onion is xor factor, but that's for *after* the
            // onion round to compute the return value, so we don't care about it.
            for (size_t j = n_hops - 1; j > i; j--)
            {
                auto onion_nonce = path_hops[i].nonce ^ path_hops[i].nonceXOR;

                crypto::onion(
                    reinterpret_cast<unsigned char*>(frame_str[j].data()),
                    frame_str[j].size(),
                    path_hops[i].shared,
                    onion_nonce,
                    onion_nonce);
            }
        }

        std::string dummy;
        dummy.reserve(last_len);
        // append dummy frames; path build request must always have MAX_LEN frames
        for (i = n_hops; i < path::MAX_LEN; i++)
        {
            frame_str[i].resize(last_len);
            randombytes(reinterpret_cast<uint8_t*>(frame_str[i].data()), frame_str[i].size());
        }

        for (auto& str : frame_str)  // NOLINT
        {
            frames.append(std::move(str));
        }

        _router.path_context().AddOwnPath(get_self(), path);
        _build_stats.attempts++;

        return std::move(frames).str();
    }

    bool PathHandler::build3(
        std::shared_ptr<Path>& path, std::string payload, std::function<void(oxen::quic::message)> handler)
    {
        return _router.send_control_message(path->upstream(), "path_build", std::move(payload), std::move(handler));
    }

    void PathHandler::build(std::vector<RemoteRC> hops)
    {
        if (auto new_path = build1(hops); new_path != nullptr)
        {
            auto payload = build2(new_path);
            auto terminus = new_path->terminus();

            if (not build3(new_path, std::move(payload), [this, new_path, terminus](oxen::quic::message m) {
                    if (m)
                    {
                        path_build_succeeded(terminus, new_path);
                        return;
                    }

                    try
                    {
                        // TODO: inform failure (what this means needs revisiting, badly)
                        if (m.timed_out)
                        {
                            log::warning(logcat, "Path build request timed out!");
                            path_build_failed(terminus, new_path, true);
                        }
                        else
                        {
                            oxenc::bt_dict_consumer d{m.body()};
                            auto status = d.require<std::string_view>(messages::STATUS_KEY);
                            log::warning(logcat, "Path build returned failure status: {}", status);
                            path_build_failed(terminus, new_path);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        log::warning(logcat, "Exception caught parsing path build response: {}", e.what());
                    }
                }))
            {
                log::warning(logcat, "Error sending path_build control message");
                path_build_failed(terminus, new_path);
            }
        }
    }

    void PathHandler::drop_path(const RouterID& remote)
    {
        Lock_t l{paths_mutex};

        if (auto itr = _paths.find(remote); itr != _paths.end())
        {
            dissociate_hop_ids(itr->second);
            _paths.erase(itr);
        }
    }

    void PathHandler::path_build_failed(const RouterID& remote, std::shared_ptr<Path> p, bool timeout)
    {
        drop_path(remote);

        if (timeout)
        {
            _router.router_profiling().path_timeout(p.get());
            _build_stats.timeouts += 1;
        }
        else
            _build_stats.build_fails -= 1;

        path_build_backoff();
    }

    void PathHandler::path_build_succeeded(const RouterID& remote, std::shared_ptr<Path> p)
    {
        add_path(remote, p);
        build_interval_limit = PATH_BUILD_RATE;
        _router.router_profiling().path_success(p.get());
        _build_stats.success += 1;
    }

    void PathHandler::path_build_backoff()
    {
        static constexpr std::chrono::milliseconds MaxBuildInterval = 30s;
        // linear backoff
        build_interval_limit = std::min(PATH_BUILD_RATE + build_interval_limit, MaxBuildInterval);
        log::warning(logcat, "{} build interval is now {}", name(), build_interval_limit);
    }

    void PathHandler::path_died(std::shared_ptr<Path> p)
    {
        log::warning(logcat, "{} path {} died post-build", name(), p->to_string());
        _build_stats.path_fails++;
    }

    void PathHandler::associate_hop_ids(std::shared_ptr<Path> p)
    {
        for (const auto& h : p->hops)
        {
            auto rid = p->pivot_router_id();
            _path_lookup.emplace(h.rxID, rid);
            _path_lookup.emplace(h.txID, rid);
        }
    }

    void PathHandler::dissociate_hop_ids(std::shared_ptr<Path> p)
    {
        for (const auto& h : p->hops)
        {
            _path_lookup.erase(h.txID);
            _path_lookup.erase(h.rxID);
        }
    }

}  // namespace llarp::path
