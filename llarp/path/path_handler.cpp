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
#include <llarp/util/meta.hpp>

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

    nlohmann::json BuildStats::ExtractStatus() const
    {
        return nlohmann::json{
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
        log::debug(logcat, "Adding path...");
        Lock_t l(paths_mutex);

        _paths.insert_or_assign(p->upstream_rxid(), p);

        _router.path_context()->add_path(p);
    }

    void PathHandler::drop_path(const std::shared_ptr<Path>& p)
    {
        Lock_t l{paths_mutex};

        if (auto itr = _paths.find(p->upstream_rxid()); itr != _paths.end())
            _paths.erase(itr);

        _router.path_context()->drop_path(p);
    }

    std::optional<std::shared_ptr<Path>> PathHandler::get_random_path()
    {
        auto p = std::make_optional<std::pair<HopID, std::shared_ptr<path::Path>>>();

        std::sample(_paths.begin(), _paths.end(), &*p, 1, csrng);

        return p.has_value() ? std::make_optional(p->second) : std::nullopt;
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
            std::pair<HopID, std::shared_ptr<path::Path>> t;

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

    void PathHandler::reset_path_state()
    {
        build_interval_limit = PATH_BUILD_RATE;
        last_build = 0s;
    }

    // called within the scope of locked mutex
    void PathHandler::tick_paths()
    {
        Lock_t l{paths_mutex};

        const auto now = llarp::time_now_ms();

        for (auto& [_, p] : _paths)
        {
            if (p)
                p->Tick(now);
        }
    }

    std::chrono::milliseconds PathHandler::now() const
    {
        return _router.now();
    }

    // called within the scope of locked mutex
    void PathHandler::expire_paths(std::chrono::milliseconds now)
    {
        Lock_t lock{paths_mutex};

        if (_paths.size() == 0)
            return;

        std::vector<HopID> to_drop;

        for (auto itr = _paths.begin(); itr != _paths.end();)
        {
            if (itr->second and itr->second->is_established() and itr->second->is_expired(now))
            {
                to_drop.push_back(itr->second->upstream_rxid());
                to_drop.push_back(itr->second->pivot_txid());
                itr = _paths.erase(itr);
            }
            else
                ++itr;
        }

        if (not to_drop.empty())
        {
            log::debug(logcat, "{} paths expired; giving path-ctx droplist", to_drop.size());
            _router.path_context()->drop_paths(std::move(to_drop));
        }
    }

    // called within the scope of locked mutex
    std::optional<std::shared_ptr<Path>> PathHandler::get_path(HopID hid) const
    {
        if (auto itr = _paths.find(hid); itr != _paths.end())
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

    intro_set PathHandler::get_current_client_intros() const
    {
        Lock_t lock{paths_mutex};

        intro_set intros{};
        auto now = llarp::time_now_ms();

        for (const auto& [_, p] : _paths)
        {
            if (p and p->is_ready(now))
                intros.emplace(p->intro);
        }

        return intros;
    }

    void PathHandler::tick(std::chrono::milliseconds now)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        Lock_t l{paths_mutex};

        now = llarp::time_now_ms();
        _router.pathbuild_limiter().Decay(now);

        expire_paths(now);

        if (auto n = should_build_more(); n > 0)
            build_more(n);

        tick_paths();

        if (_build_stats.attempts > 50)
        {
            if (_build_stats.SuccessRatio() <= BuildStats::THRESHOLD && now - last_warn_time > 5s)
            {
                log::warning(logcat, "Low path build success: {}", _build_stats);
                last_warn_time = now;
            }
        }
    }

    nlohmann::json PathHandler::ExtractStatus() const
    {
        nlohmann::json obj{
            {"buildStats", _build_stats.ExtractStatus()},
            {"numHops", uint64_t{num_hops}},
            {"numPaths", uint64_t{num_paths_desired}}};
        std::transform(
            _paths.begin(), _paths.end(), std::back_inserter(obj["paths"]), [](const auto& item) -> nlohmann::json {
                return item.second->ExtractStatus();
            });
        return obj;
    }

    std::optional<RemoteRC> PathHandler::select_first_hop(const std::set<RouterID>& exclude) const
    {
        std::set<RouterID> current_remotes;

        if (_router.node_db()->strict_connect_enabled())
            current_remotes = _router.node_db()->pinned_edges();
        else
            current_remotes = _router.get_current_remotes();

        std::function<bool(RouterID)> hook = [&](const RouterID& rid) {
            if (exclude.count(rid))
                return false;
            if (build_cooldown_hit(rid))
                return false;
            // always returns false on testnet builds
            if (_router.router_profiling().is_bad_for_path(rid))
                return false;
            return true;
        };

        auto edge = meta::sample(current_remotes, hook);

        return edge ? _router.node_db()->get_rc(*edge) : std::nullopt;
    }

    size_t PathHandler::num_active_paths() const
    {
        Lock_t l(paths_mutex);

        size_t n{};

        for (const auto& [_, p] : _paths)
            n += (p != nullptr);

        return n;
    }

    size_t PathHandler::num_paths() const
    {
        Lock_t l(paths_mutex);

        return _paths.size();
    }

    bool PathHandler::stop(bool)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _running = false;
        _paths.clear();

        return true;
    }

    bool PathHandler::is_stopped() const
    {
        return !_running.load();
    }

    bool PathHandler::should_remove() const
    {
        return is_stopped() and num_active_paths() == 0;
    }

    bool PathHandler::build_cooldown_hit(RouterID edge) const
    {
        return _router.pathbuild_limiter().Limited(edge);
    }

    bool PathHandler::build_cooldown() const
    {
        return llarp::time_now_ms() < last_build + build_interval_limit;
    }

    size_t PathHandler::should_build_more() const
    {
        if (is_stopped())
            return {};

        if (build_cooldown())
            return {};

        auto n_paths = num_paths();

        return num_paths_desired >= n_paths ? num_paths_desired - n_paths : 0;
    }

    std::optional<std::vector<RemoteRC>> PathHandler::get_hops_to_random()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        auto filter = [&r = _router](const RemoteRC& rc) mutable {
            return not r.router_profiling().is_bad_for_path(rc.router_id(), 1);
        };

        if (auto maybe = _router.node_db()->get_random_rc_conditional(filter))
            return aligned_hops_to_remote(maybe->router_id());

        return std::nullopt;
    }

    // std::optional<std::vector<RemoteRC>> PathHandler::specific_hops_to_remote(std::vector<RouterID> specifgic)
    // {
    //     log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

    //     assert(num_hops);

    //     auto hops_needed = num_hops;
    //     std::vector<RemoteRC> hops{};

    // }

    std::optional<std::vector<RemoteRC>> PathHandler::aligned_hops_between(const RouterID& edge, const RouterID& pivot)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        assert(num_hops);
        auto hops_needed = num_hops;

        if (hops_needed == 1)
        {
            log::error(logcat, "Stop using debug methods for stupid path structures");
            return std::nullopt;
        }

        std::vector<RemoteRC> hops{};

        RemoteRC pivot_rc{};

        if (auto maybe = _router.node_db()->get_rc(pivot))
        {
            // leave space to add the pivot last
            --hops_needed;
            pivot_rc = std::move(*maybe);
        }
        else
            return std::nullopt;

        if (auto maybe = _router.node_db()->get_rc(edge))
        {
            // leave space to add the pivot last
            --hops_needed;
            hops.emplace_back(std::move(*maybe));
        }
        else
            return std::nullopt;

        auto filter = [&](const RemoteRC& rc) -> bool {
            const auto& rid = rc.router_id();

            if (rid == edge || rid == pivot)
                return false;

            return true;
        };

        if (auto maybe_rcs = _router.node_db()->get_n_random_rcs_conditional(hops_needed, filter))
        {
            log::info(logcat, "Found {} RCs for aligned path (needed: {})", maybe_rcs->size(), hops_needed);
            hops.insert(hops.end(), maybe_rcs->begin(), maybe_rcs->end());
            hops.emplace_back(std::move(pivot_rc));
            return hops;
        }

        log::warning(logcat, "Failed to find RC for aligned path! (needed:{})", num_hops);
        return std::nullopt;
    }

    std::optional<std::vector<RemoteRC>> PathHandler::aligned_hops_to_remote(
        const RouterID& pivot, const std::set<RouterID>& exclude)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        assert(num_hops);

        auto hops_needed = num_hops;

        std::vector<RemoteRC> hops{};
        RemoteRC pivot_rc{};

        if (auto maybe = _router.node_db()->get_rc(pivot))
        {
            // if we only need one hop, return
            if (hops_needed == 1)
            {
                hops.emplace_back(std::move(*maybe));
                return hops;
            }

            // leave space to add the pivot last
            --hops_needed;
            pivot_rc = *maybe;
        }
        else
            return std::nullopt;

        auto netmask = _router.config()->paths.unique_hop_netmask;

        // make a copy here to reference rather than creating one in the lambda every iteration
        std::set<RouterID> to_exclude{exclude.begin(), exclude.end()};
        to_exclude.insert(pivot);
        std::vector<ipv4_range> excluded_ranges{};
        excluded_ranges.emplace_back(pivot_rc.addr().to_ipv4() / netmask);

        if (auto maybe = select_first_hop(to_exclude))
        {
            hops.push_back(*maybe);
            excluded_ranges.emplace_back(maybe->addr().to_ipv4() / netmask);
            --hops_needed;
        }
        else
        {
            log::warning(logcat, "No first hop candidate for aligned hops!");
            return std::nullopt;
        }

        to_exclude.insert(hops.back().router_id());

        auto filter = [&](const RemoteRC& rc) -> bool {
            const auto& rid = rc.router_id();
            auto v4 = rc.addr().to_ipv4();

            for (auto& e : excluded_ranges)
            {
                if (e.contains(v4))
                    return false;
            }

            excluded_ranges.emplace_back(v4 / netmask);

            // if its already excluded, fail; (we want it added even on success)
            if (not to_exclude.insert(rid).second)
                return false;

            if (_router.router_profiling().is_bad_for_path(rid, 1))
                return false;

            return true;
        };

        log::debug(logcat, "First/last hop selected, {} hops remaining to select", hops_needed);

        if (auto maybe_hops = _router.node_db()->get_n_random_rcs_conditional(hops_needed, filter))
        {
            log::info(logcat, "Found {} RCs for aligned path (needed: {})", maybe_hops->size(), hops_needed);
            hops.insert(hops.end(), maybe_hops->begin(), maybe_hops->end());
            hops.emplace_back(std::move(pivot_rc));
            return hops;
        }

        log::warning(logcat, "Failed to find {} RCs for aligned path to pivot: {}", hops_needed, pivot);
        return std::nullopt;

        while (hops_needed)
        {
            // do this 1 at a time so we can check for IP range overlap
            if (auto maybe_rc = _router.node_db()->get_random_rc_conditional(filter))
            {
                hops.emplace_back(std::move(*maybe_rc));
            }
            else
            {
                log::warning(
                    logcat, "Failed to find RC for aligned path! (needed:{}, remaining:{})", num_hops, hops_needed);

                if (not hops.empty())
                {
                    for (auto& h : hops)
                        log::info(logcat, "{}", h);
                }
                return std::nullopt;
            }

            --hops_needed;
        }

        // add pivot rc last
        hops.emplace_back(std::move(pivot_rc));

        return hops;
    }

    bool PathHandler::build_path_to_random()
    {
        Lock_t l(paths_mutex);

        if (auto maybe_hops = get_hops_to_random())
        {
            build(*maybe_hops);
            return true;
        }

        log::warning(logcat, "Failed to get hops for path-build to random");
        return false;
    }

    bool PathHandler::build_path_aligned_to_remote(const RouterID& remote)
    {
        Lock_t l(paths_mutex);

        if (auto maybe_hops = aligned_hops_to_remote(remote))
        {
            build(*maybe_hops);
            return true;
        }

        log::warning(logcat, "Failed to get hops for path-build to {}", remote);
        return false;
    }

    bool PathHandler::pre_build(std::vector<RemoteRC>& hops)
    {
        if (is_stopped())
        {
            log::info(logcat, "Path builder is stopped, aborting path build...");
            return false;
        }

        last_build = llarp::time_now_ms();
        const auto& edge = hops[0].router_id();

        if (not _router.pathbuild_limiter().Attempt(edge))
        {
            log::warning(logcat, "Building too quickly to edge router {}", edge);
            return false;
        }

        return true;
    }

    std::shared_ptr<Path> PathHandler::build1(std::vector<RemoteRC>& hops)
    {
        auto path = std::make_shared<path::Path>(_router, hops, get_weak());

        {
            Lock_t l{paths_mutex};

            if (auto [it, b] = _paths.try_emplace(path->upstream_rxid(), nullptr); not b)
            {
                log::warning(logcat, "Pending build to {} already underway... aborting...", path->upstream_rxid());
                return nullptr;
            }
        }

        log::info(logcat, "Building path -> {} : {}", path->to_string(), path->hop_string());

        return path;
    }

    std::string PathHandler::build2(const std::shared_ptr<Path>& path)
    {
        std::vector<std::string> frames(path::MAX_LEN);
        auto& path_hops = path->hops;
        int n_hops = static_cast<int>(path->num_hops);
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

        // i from n_hops down to 0
        for (int i = n_hops - 1; i >= 0; --i)
        {
            frames[i] = PATH::BUILD::serialize_hop(path_hops[i]);

            if (last_len and frames[i].size() != last_len)
            {
                assert(frames[i].size() == last_len);
                log::critical(logcat, "All frames must be the same length!");
            }

            last_len = frames[i].size();

            for (auto j = i + 1; j < n_hops; ++j)
            {
                auto _onion_nonce = path_hops[i].nonce ^ path_hops[i].nonceXOR;

                crypto::onion(
                    reinterpret_cast<unsigned char*>(frames[j].data()),
                    frames[j].size(),
                    path_hops[i].shared,
                    _onion_nonce,
                    _onion_nonce);
            }
        }

        // append dummy frames; path build request must always have MAX_LEN frames
        for (size_t i = n_hops; i < path::MAX_LEN; ++i)
        {
            frames[i].resize(last_len);
            randombytes(reinterpret_cast<uint8_t*>(frames[i].data()), frames[i].size());
        }

        _build_stats.attempts++;

        return ONION::serialize_frames(std::move(frames));
    }

    bool PathHandler::build3(RouterID upstream, std::string payload, std::function<void(oxen::quic::message)> handler)
    {
        return _router.send_control_message(std::move(upstream), "path_build", std::move(payload), std::move(handler));
    }

    // called within the scope of a locked mutex
    void PathHandler::build(std::vector<RemoteRC> hops)
    {
        // error message logs in function scope
        if (not pre_build(hops))
            return;

        if (auto new_path = build1(hops))
        {
            assert(new_path);

            auto payload = build2(new_path);
            auto upstream = new_path->upstream_rid();

            if (not build3(std::move(upstream), std::move(payload), [this, new_path](oxen::quic::message m) mutable {
                    if (m)
                    {
                        log::critical(logcat, "PATH ESTABLISHED: {}", new_path->hop_string());
                        return path_build_succeeded(std::move(new_path));
                    }

                    try
                    {
                        // TODO: inform failure (what this means needs revisiting, badly)
                        if (m.timed_out)
                        {
                            log::warning(logcat, "Path build request timed out!");
                        }
                        else
                        {
                            oxenc::bt_dict_consumer d{m.body()};
                            auto status = d.require<std::string_view>(messages::STATUS_KEY);
                            log::warning(logcat, "Path build returned failure status: {}", status);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        log::warning(
                            logcat, "Exception caught parsing path build response: {}; input: {}", e.what(), m.body());
                    }

                    path_build_failed(std::move(new_path), m.timed_out);
                }))
            {
                log::warning(logcat, "Error sending path_build control message");
                path_build_failed(new_path);
            }
        }
    }

    void PathHandler::path_build_failed(std::shared_ptr<Path> p, bool timeout)
    {
        drop_path(p);

        if (timeout)
        {
            _router.router_profiling().path_timeout(p.get());
            _build_stats.timeouts += 1;
        }
        else
            _build_stats.build_fails += 1;

        path_build_backoff();
    }

    void PathHandler::path_build_succeeded(std::shared_ptr<Path> p)
    {
        p->set_established();
        add_path(p);
        build_interval_limit = PATH_BUILD_RATE;
        _router.router_profiling().path_success(p.get());
        _build_stats.success += 1;
    }

    void PathHandler::path_build_backoff()
    {
        static constexpr std::chrono::milliseconds MaxBuildInterval = 30s;
        // linear backoff
        build_interval_limit = std::min(PATH_BUILD_RATE + build_interval_limit, MaxBuildInterval);
        log::warning(logcat, "Build interval is now {}", build_interval_limit);
    }

    void PathHandler::path_died(std::shared_ptr<Path> p)
    {
        log::warning(logcat, "Path {} died post-build", p->to_string());
        _build_stats.path_fails++;
    }
}  // namespace llarp::path
