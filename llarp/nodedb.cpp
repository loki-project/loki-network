#include "nodedb.hpp"

#include "crypto/types.hpp"
#include "dht/kademlia.hpp"
#include "link/link_manager.hpp"
#include "messages/fetch.hpp"
#include "router_contact.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <unordered_map>
#include <utility>

static const std::string RC_FILE_EXT = ".signed";

namespace llarp
{
    static void EnsureSkiplist(fs::path nodedbDir)
    {
        if (not fs::exists(nodedbDir))
        {
            // if the old 'netdb' directory exists, move it to this one
            fs::path parent = nodedbDir.parent_path();
            fs::path old = parent / "netdb";
            if (fs::exists(old))
                fs::rename(old, nodedbDir);
            else
                fs::create_directory(nodedbDir);
        }

        if (not fs::is_directory(nodedbDir))
            throw std::runtime_error{fmt::format("nodedb {} is not a directory", nodedbDir)};
    }

    NodeDB::NodeDB(fs::path root, std::function<void(std::function<void()>)> diskCaller, Router* r)
        : _router{*r},
          _root{std::move(root)},
          _disk(std::move(diskCaller)),
          _next_flush_time{time_now_ms() + FLUSH_INTERVAL}
    {
        EnsureSkiplist(_root);
        fetch_counters.clear();
    }

    std::tuple<size_t, size_t, size_t> NodeDB::db_stats() const
    {
        return {num_rcs(), num_rids(), num_bootstraps()};
    }

    std::optional<RemoteRC> NodeDB::get_rc_by_rid(const RouterID& rid)
    {
        if (auto itr = rc_lookup.find(rid); itr != rc_lookup.end())
            return itr->second;

        return std::nullopt;
    }

    std::optional<RemoteRC> NodeDB::get_random_rc() const
    {
        std::optional<RemoteRC> rand = std::nullopt;

        std::sample(known_rcs.begin(), known_rcs.end(), &*rand, 1, csrng);
        return rand;
    }

    std::optional<std::vector<RemoteRC>> NodeDB::get_n_random_rcs(size_t n, bool exact) const
    {
        auto rand = std::make_optional<std::vector<RemoteRC>>();
        rand->reserve(n);

        std::sample(known_rcs.begin(), known_rcs.end(), std::back_inserter(*rand), n, csrng);
        if (rand->size() < (exact ? n : 1))
            rand.reset();
        return rand;
    }

    std::optional<RemoteRC> NodeDB::get_random_rc_conditional(std::function<bool(RemoteRC)> hook) const
    {
        std::optional<RemoteRC> rand = get_random_rc();

        if (rand and hook(*rand))
            return rand;

        size_t i = 0;

        for (const auto& rc : known_rcs)
        {
            if (not hook(rc))
                continue;

            if (++i <= 1)
            {
                rand = rc;
                continue;
            }

            size_t x = csrng() % (i + 1);
            if (x <= 1)
                rand = rc;
        }

        return rand;
    }

    std::optional<std::vector<RemoteRC>> NodeDB::get_n_random_rcs_conditional(
        size_t n, std::function<bool(RemoteRC)> hook, bool exact) const
    {
        auto selected = std::make_optional<std::vector<RemoteRC>>();
        selected->reserve(n);

        size_t i = 0;

        for (const auto& rc : known_rcs)
        {
            // ignore any RC's that do not pass the condition
            if (not hook(rc))
                continue;

            // load the first n RC's that pass the condition into selected
            if (++i <= n)
            {
                selected->push_back(rc);
                continue;
            }

            // replace selections with decreasing probability per iteration
            size_t x = csrng() % (i + 1);
            if (x < n)
                (*selected)[x] = rc;
        }

        if (selected->size() < (exact ? n : 1))
            selected.reset();
        return selected;
    }

    void NodeDB::Tick(llarp_time_t now)
    {
        if (_next_flush_time == 0s)
            return;

        if (now > _next_flush_time)
        {
            _router.loop()->call([this]() {
                _next_flush_time += FLUSH_INTERVAL;
                // make copy of all rcs
                std::vector<RemoteRC> copy;

                for (const auto& item : rc_lookup)
                    copy.push_back(item.second);

                // flush them to disk in one big job
                // TODO: split this up? idk maybe some day...
                _disk([this, data = std::move(copy)]() {
                    for (const auto& rc : data)
                        rc.write(get_path_by_pubkey(rc.router_id()));
                });
            });
        }
    }

    fs::path NodeDB::get_path_by_pubkey(const RouterID& pubkey) const
    {
        return _root / (pubkey.ToString() + RC_FILE_EXT);
    }

    bool NodeDB::want_rc(const RouterID& rid) const
    {
        if (not _router.is_service_node())
            return true;

        return known_rids.count(rid);
    }

    void NodeDB::set_bootstrap_routers(BootstrapList& from_router)
    {
        _bootstraps.merge(from_router);
        _bootstraps.randomize();
    }

    bool NodeDB::process_fetched_rcs(std::set<RemoteRC>& rcs)
    {
        std::set<RemoteRC> confirmed_set, unconfirmed_set;

        // the intersection of local RC's and received RC's is our confirmed set
        std::set_intersection(
            known_rcs.begin(),
            known_rcs.end(),
            rcs.begin(),
            rcs.end(),
            std::inserter(confirmed_set, confirmed_set.begin()));

        // the intersection of the confirmed set and received RC's is our unconfirmed set
        std::set_intersection(
            rcs.begin(),
            rcs.end(),
            confirmed_set.begin(),
            confirmed_set.end(),
            std::inserter(unconfirmed_set, unconfirmed_set.begin()));

        // the total number of rcs received
        const auto num_received = static_cast<double>(rcs.size());
        // the number of returned "good" rcs (that are also found locally)
        const auto inter_size = confirmed_set.size();

        const auto fetch_threshold = (double)inter_size / num_received;

        /** We are checking 2 things here:
            1) The number of "good" rcs is above MIN_GOOD_RC_FETCH_TOTAL
            2) The ratio of "good" rcs to total received is above MIN_GOOD_RC_FETCH_THRESHOLD
        */
        bool success = false;
        if (success = inter_size > MIN_GOOD_RC_FETCH_TOTAL and fetch_threshold > MIN_GOOD_RC_FETCH_THRESHOLD; success)
        {
            // set rcs to be intersection set
            rcs = std::move(confirmed_set);

            process_results(std::move(unconfirmed_set), unconfirmed_rcs, known_rcs);
        }

        return success;
    }

    bool NodeDB::ingest_fetched_rcs(std::set<RemoteRC> rcs)
    {
        // if we are not bootstrapping, we should check the rc's against the ones we currently hold
        if (not _using_bootstrap_fallback)
        {
            log::critical(logcat, "Checking returned RCs against locally held...");

            auto success = process_fetched_rcs(rcs);

            log::critical(logcat, "RCs returned by FetchRC {} by trust model", success ? "approved" : "rejected");
            return success;
        }

        while (!rcs.empty())
            put_rc_if_newer(std::move(rcs.extract(rcs.begin()).value()));

        return true;
    }

    /** We only call into this function after ensuring two conditions:
          1) We have received all 12 responses from the queried RouterID sources, whether that
            response was a timeout or not
          2) Of those responses, less than 4 were errors of any sorts

        Upon receiving each response from the rid fetch sources, the returned rid's are incremented
        in fetch_counters. This greatly simplifies the analysis required by this function to the
        determine success or failure:
          - If the frequency of each rid is above a threshold, it is accepted
          - If the number of accepted rids is below a certain amount, the set is rejected

        Logically, this function performs the following basic analysis of the returned RIDs:
          1) All responses are coalesced into a union set with no repetitions
          2) If we are bootstrapping:
              - The routerID's returned
    */
    bool NodeDB::process_fetched_rids()
    {
        std::set<RouterID> union_set, confirmed_set, unconfirmed_set;

        for (const auto& [rid, count] : fetch_counters)
        {
            if (count > MIN_RID_FETCH_FREQ)
                union_set.insert(rid);
            else
                unconfirmed_set.insert(rid);
        }

        // get the intersection of accepted rids and local rids
        std::set_intersection(
            known_rids.begin(),
            known_rids.end(),
            union_set.begin(),
            union_set.end(),
            std::inserter(confirmed_set, confirmed_set.begin()));

        // the total number of rids received
        const auto num_received = (double)fetch_counters.size();
        // the total number of received AND accepted rids
        const auto union_size = union_set.size();

        const auto fetch_threshold = (double)union_size / num_received;

        /** We are checking 2 things here:
            1) The ratio of received/accepted to total received is above GOOD_RID_FETCH_THRESHOLD.
               This tells us how well the rid source's sets of rids "agree" with one another
            2) The total number received is above MIN_RID_FETCH_TOTAL. This ensures that we are
               receiving a sufficient amount to make a comparison of any sorts
        */
        bool success = false;
        if (success = (fetch_threshold > GOOD_RID_FETCH_THRESHOLD) and (union_size > MIN_GOOD_RID_FETCH_TOTAL); success)
        {
            process_results(std::move(unconfirmed_set), unconfirmed_rids, known_rids);

            known_rids.merge(confirmed_set);
        }

        return success;
    }

    void NodeDB::ingest_rid_fetch_responses(const RouterID& source, std::set<RouterID> rids)
    {
        if (rids.empty())
        {
            fail_sources.insert(source);
            return;
        }

        for (const auto& rid : rids)
            fetch_counters[rid] += 1;
    }

    void NodeDB::fetch_initial(bool is_snode)
    {
        auto sz = num_rcs();

        if (sz < MIN_ACTIVE_RCS)
        {
            log::critical(logcat, "{}/{} RCs held locally... BOOTSTRAP TIME", sz, MIN_ACTIVE_RCS);
            fallback_to_bootstrap();
        }
        else if (is_snode)
        {
            // service nodes who have sufficient local RC's can bypass initial fetching
            _needs_initial_fetch = false;
        }
        else
        {
            _fetching_initial = true;
            // Set fetch source as random selection of known active client routers
            fetch_source = *std::next(known_rids.begin(), csrng() % known_rids.size());
            fetch_rcs(true);
        }
    }

    void NodeDB::fetch_rcs(bool initial)
    {
        auto& num_failures = fetch_failures;

        // base case; this function is called recursively
        if (num_failures > MAX_FETCH_ATTEMPTS)
        {
            fetch_rcs_result(initial, true);
            return;
        }

        std::vector<RouterID> needed;
        const auto now = time_point_now();

        if (not initial)
        {
            for (const auto& [rid, rc] : rc_lookup)
            {
                if (now - rc.timestamp() > RouterContact::OUTDATED_AGE)
                    needed.push_back(rid);
            }
        }

        RouterID& src = fetch_source;
        log::critical(
            logcat,
            "Sending{} FetchRCs request to {} for {} RCs",
            initial ? " initial" : "",
            src,
            initial ? "all of the" : std::to_string(needed.size()));

        if (initial)
            _router.next_initial_fetch_attempt = now + INITIAL_ATTEMPT_INTERVAL;

        _router.last_rc_fetch = now;

        _router.link_manager().fetch_rcs(
            src,
            FetchRCMessage::serialize(_router.last_rc_fetch, needed),
            [this, source = src, initial](oxen::quic::message m) mutable {
                if (m.timed_out)
                {
                    log::critical(logcat, "RC fetch to {} timed out!", source);
                    fetch_rcs_result(initial, m.timed_out);
                    return;
                }
                try
                {
                    oxenc::bt_dict_consumer btdc{m.body()};
                    // TODO: can this just combine with the above failure case...?
                    if (m.is_error())
                    {
                        auto reason = btdc.require<std::string_view>(messages::STATUS_KEY);
                        log::critical(logcat, "RC fetch to {} returned error: {}", source, reason);
                        fetch_rcs_result(initial, m.is_error());
                        return;
                    }

                    auto btlc = btdc.require<oxenc::bt_list_consumer>("rcs"sv);

                    std::set<RemoteRC> rcs;

                    while (not btlc.is_finished())
                        rcs.emplace(btlc.consume_dict_data());

                    // if process_fetched_rcs returns false, then the trust model rejected the
                    // fetched RC's
                    fetch_rcs_result(initial, not ingest_fetched_rcs(std::move(rcs)));
                }
                catch (const std::exception& e)
                {
                    log::critical(logcat, "Failed to parse RC fetch response from {}: {}", source, e.what());
                    fetch_rcs_result(initial, true);
                    return;
                }
            });
    }

    void NodeDB::fetch_rids(bool initial)
    {
        // base case; this function is called recursively
        if (fetch_failures > MAX_FETCH_ATTEMPTS)
        {
            fetch_rids_result(initial);
            return;
        }

        if (rid_sources.empty())
        {
            reselect_router_id_sources(rid_sources);
        }

        if (not initial and rid_sources.empty())
        {
            log::error(logcat, "Attempting to fetch RouterIDs, but have no source from which to do so.");
            fallback_to_bootstrap();
            return;
        }

        fetch_counters.clear();

        RouterID& src = fetch_source;
        _router.last_rid_fetch = llarp::time_point_now();

        for (const auto& target : rid_sources)
        {
            log::critical(logcat, "Sending FetchRIDs request to {} via {}", target, src);
            _router.link_manager().fetch_router_ids(
                src,
                FetchRIDMessage::serialize(target),
                [this, source = src, target, initial](oxen::quic::message m) mutable {
                    if (m.is_error())
                    {
                        auto err =
                            "RID fetch from {} via {} {}"_format(target, source, m.timed_out ? "timed out" : "failed");
                        log::critical(link_cat, err);
                        ingest_rid_fetch_responses(target);
                        fetch_rids_result(initial);
                        return;
                    }

                    try
                    {
                        oxenc::bt_dict_consumer btdc{m.body()};

                        btdc.required("routers");
                        auto router_id_strings = btdc.consume_list<std::vector<ustring>>();

                        btdc.require_signature("signature", [&source](ustring_view msg, ustring_view sig) {
                            if (sig.size() != 64)
                                throw std::runtime_error{"Invalid signature: not 64 bytes"};
                            if (not crypto::verify(source, msg, sig))
                                throw std::runtime_error{"Failed to verify signature for fetch RouterIDs response."};
                        });

                        std::set<RouterID> router_ids;

                        for (const auto& s : router_id_strings)
                        {
                            if (s.size() != RouterID::SIZE)
                            {
                                log::critical(
                                    link_cat, "RID fetch from {} via {} returned bad RouterID", target, source);
                                ingest_rid_fetch_responses(target);
                                fetch_rids_result(initial);
                                return;
                            }

                            router_ids.emplace(s.data());
                        }

                        ingest_rid_fetch_responses(target, std::move(router_ids));
                        fetch_rids_result(initial);  // success
                        return;
                    }
                    catch (const std::exception& e)
                    {
                        log::critical(link_cat, "Error handling fetch RouterIDs response: {}", e.what());
                        ingest_rid_fetch_responses(target);
                        fetch_rids_result(initial);
                    }
                });
        }
    }

    void NodeDB::fetch_rcs_result(bool initial, bool error)
    {
        if (error)
        {
            if (++fetch_failures >= MAX_FETCH_ATTEMPTS)
            {
                log::critical(
                    logcat,
                    "RC fetching from {} reached failure threshold ({}); falling back to "
                    "bootstrap...",
                    fetch_source,
                    MAX_FETCH_ATTEMPTS);

                fallback_to_bootstrap();
                return;
            }

            if (initial)
                _needs_initial_fetch = true;

            // If we have passed the last last conditional, then it means we are not bootstrapping
            // and the current fetch_source has more attempts before being rotated. As a result, we
            // find new non-bootstrap RC fetch source and try again buddy
            fetch_source = (initial) ? *std::next(known_rids.begin(), csrng() % known_rids.size())
                                     : std::next(rc_lookup.begin(), csrng() % rc_lookup.size())->first;

            fetch_rcs(initial);
        }
        else
        {
            log::critical(logcat, "Successfully fetched RC's from {}", fetch_source);
            post_fetch_rcs(initial);
        }
    }

    void NodeDB::fetch_rids_result(bool initial)
    {
        if (fetch_failures >= MAX_FETCH_ATTEMPTS)
        {
            log::critical(
                logcat,
                "Failed {} attempts to fetch RID's from {}; reverting to bootstrap...",
                MAX_FETCH_ATTEMPTS,
                fetch_source);

            fallback_to_bootstrap();
            return;
        }

        auto n_responses = RID_SOURCE_COUNT - fail_sources.size();

        if (n_responses < RID_SOURCE_COUNT)
        {
            log::critical(logcat, "Received {}/{} fetch RID requests", n_responses, RID_SOURCE_COUNT);
            return;
        }

        auto n_fails = fail_sources.size();

        if (n_fails <= MAX_RID_ERRORS)
        {
            log::critical(logcat, "RID fetching was successful ({}/{} acceptable errors)", n_fails, MAX_RID_ERRORS);

            // this is where the trust model will do verification based on the similarity of the
            // sets
            if (process_fetched_rids())
            {
                log::critical(logcat, "Accumulated RID's accepted by trust model");
                post_fetch_rids(initial);
                return;
            }

            log::critical(logcat, "Accumulated RID's rejected by trust model, reselecting all RID sources...");
            reselect_router_id_sources(rid_sources);
            ++fetch_failures;
        }
        else
        {
            // we had 4 or more failed requests, so we will need to rotate our rid sources
            log::critical(logcat, "RID fetching found {} failures; reselecting failed RID sources...", n_fails);
            ++fetch_failures;
            reselect_router_id_sources(fail_sources);
        }

        fetch_rids(initial);
    }

    // This function is only called after a successful FetchRC request
    void NodeDB::post_fetch_rcs(bool initial)
    {
        _needs_rebootstrap = false;
        _needs_initial_fetch = false;
        _using_bootstrap_fallback = false;
        fail_sources.clear();
        fetch_failures = 0;

        if (initial)
            fetch_rids(initial);
    }

    void NodeDB::post_fetch_rids(bool initial)
    {
        fail_sources.clear();
        fetch_failures = 0;
        fetch_counters.clear();
        _needs_rebootstrap = false;
        _using_bootstrap_fallback = false;

        if (initial)
        {
            _needs_initial_fetch = false;
            _fetching_initial = false;
            _initial_completed = true;
        }
    }

    void NodeDB::fallback_to_bootstrap()
    {
        log::critical(logcat, "{} called", __PRETTY_FUNCTION__);
        auto at_max_failures = bootstrap_attempts >= MAX_BOOTSTRAP_FETCH_ATTEMPTS;

        // base case: we have failed to query all bootstraps, or we received a sample of
        // the network, but the sample was unusable or unreachable. We will also enter this
        // if we are on our first fallback to bootstrap so we can set the fetch_source (by
        // checking not using_bootstrap_fallback)
        if (at_max_failures || not _using_bootstrap_fallback)
        {
            bootstrap_attempts = 0;

            // Fail case: if we have returned to the front of the bootstrap list, we're in a
            // bad spot; we are unable to do anything
            if (_using_bootstrap_fallback)
            {
                auto err = fmt::format("ERROR: ALL BOOTSTRAPS ARE BAD... REATTEMPTING IN {}...", BOOTSTRAP_COOLDOWN);
                log::error(logcat, err);

                bootstrap_cooldown();
                return;
            }
        }

        auto& rc = (_using_bootstrap_fallback) ? _bootstraps.next() : _bootstraps.current();
        fetch_source = rc.router_id();

        // By passing the last conditional, we ensure this is set to true
        _using_bootstrap_fallback = true;
        _needs_rebootstrap = false;
        ++bootstrap_attempts;

        log::critical(logcat, "Dispatching BootstrapRC fetch request to {}", fetch_source);

        auto is_snode = _router.is_service_node();

        auto num_needed = is_snode ? SERVICE_NODE_BOOTSTRAP_SOURCE_COUNT : CLIENT_BOOTSTRAP_SOURCE_COUNT;

        _router.link_manager().fetch_bootstrap_rcs(
            rc,
            BootstrapFetchMessage::serialize(
                is_snode ? std::make_optional(_router.router_contact) : std::nullopt, num_needed),
            [this, is_snode = _router.is_service_node(), src = rc.router_id()](oxen::quic::message m) mutable {
                log::critical(logcat, "Received response to BootstrapRC fetch request...");

                if (not m)
                {
                    log::warning(
                        logcat,
                        "BootstrapRC fetch request to {} failed (error {}/{}): {}",
                        src,
                        bootstrap_attempts,
                        MAX_BOOTSTRAP_FETCH_ATTEMPTS,
                        m.body());
                    // fallback_to_bootstrap();
                    return;
                }

                size_t num = 0;

                try
                {
                    oxenc::bt_dict_consumer btdc{m.body()};

                    {
                        auto btlc = btdc.require<oxenc::bt_list_consumer>("rcs"sv);

                        while (not btlc.is_finished())
                        {
                            auto rc = RemoteRC{btlc.consume_dict_data()};
                            put_rc(rc);
                            ++num;
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    log::warning(
                        logcat,
                        "Failed to parse BootstrapRC fetch response from {} (error {}/{}): {}",
                        src,
                        bootstrap_attempts,
                        MAX_BOOTSTRAP_FETCH_ATTEMPTS,
                        e.what());
                    // fallback_to_bootstrap();
                    return;
                }

                log::critical(
                    logcat, "BootstrapRC fetch response from {} returned {}/{} needed RCs", src, num, MIN_ACTIVE_RCS);

                if (not is_snode)
                {
                    log::critical(
                        logcat,
                        "Client completed processing BootstrapRC fetch; proceeding to initial "
                        "fetch");
                    fetch_initial();
                }
                else
                {
                    log::critical(logcat, "Service node completed processing BootstrapRC fetch!");
                    post_snode_bootstrap();
                }
            });
    }

    void NodeDB::post_snode_bootstrap()
    {
        _needs_rebootstrap = false;
        _using_bootstrap_fallback = false;
        _needs_initial_fetch = false;
    }

    void NodeDB::bootstrap_cooldown()
    {
        _needs_rebootstrap = true;
        _using_bootstrap_fallback = false;
        _router.next_bootstrap_attempt = llarp::time_point_now() + BOOTSTRAP_COOLDOWN;
    }

    void NodeDB::reselect_router_id_sources(std::set<RouterID> specific)
    {
        replace_subset(rid_sources, specific, known_rids, RID_SOURCE_COUNT, csrng);
    }

    void NodeDB::set_router_whitelist(
        const std::vector<RouterID>& whitelist,
        const std::vector<RouterID>& greylist,
        const std::vector<RouterID>& greenlist)
    {
        log::critical(
            logcat,
            "Oxend provided {}/{}/{} (white/gray/green) routers",
            whitelist.size(),
            greylist.size(),
            greenlist.size());

        if (whitelist.empty())
            return;

        _registered_routers.clear();
        _registered_routers.insert(whitelist.begin(), whitelist.end());
        _registered_routers.insert(greylist.begin(), greylist.end());
        _registered_routers.insert(greenlist.begin(), greenlist.end());

        _router_whitelist.clear();
        _router_whitelist.insert(whitelist.begin(), whitelist.end());
        _router_greylist.clear();
        _router_greylist.insert(greylist.begin(), greylist.end());
        _router_greenlist.clear();
        _router_greenlist.insert(greenlist.begin(), greenlist.end());

        log::critical(
            logcat,
            "Service node holding {}:{} (whitelist:registered) after oxend integration",
            _router_whitelist.size(),
            _registered_routers.size());
    }

    std::optional<RouterID> NodeDB::get_random_whitelist_router() const
    {
        std::optional<RouterID> rand = std::nullopt;

        std::sample(_router_whitelist.begin(), _router_whitelist.end(), &*rand, 1, csrng);
        return rand;
    }

    bool NodeDB::is_connection_allowed(const RouterID& remote) const
    {
        if (not _router.is_service_node())
        {
            if (_pinned_edges.size() && _pinned_edges.count(remote) == 0 && not _bootstraps.contains(remote))
                return false;
        }

        // TESTNET: make this check an updated registry
        return known_rids.count(remote) or _registered_routers.count(remote);
    }

    bool NodeDB::is_first_hop_allowed(const RouterID& remote) const
    {
        if (_pinned_edges.size() && _pinned_edges.count(remote) == 0)
            return false;

        return true;
    }

    void NodeDB::store_bootstraps()
    {
        if (_bootstraps.empty())
            return;

        for (const auto& rc : _bootstraps)
        {
            put_rc(rc);
        }

        log::critical(logcat, "NodeDB stored {} bootstrap routers", _bootstraps.size());
    }

    void NodeDB::load_from_disk()
    {
        if (_root.empty())
            return;

        std::vector<fs::path> purge;

        const auto now = time_now_ms();

        for (const auto& f : fs::directory_iterator{_root})
        {
            if (not f.is_regular_file() or f.path().extension() != RC_FILE_EXT)
                continue;

            RemoteRC rc{};

            if (not rc.read(f) or rc.is_expired(now))
            {
                // try loading it, purge it if it is junk or expired
                purge.push_back(f);
                continue;
            }

            const auto& rid = rc.router_id();

            auto [itr, b] = known_rcs.insert(std::move(rc));
            rc_lookup.emplace(rid, *itr);
            known_rids.insert(rid);
        }

        if (not purge.empty())
        {
            log::warning(logcat, "removing {} invalid RCs from disk", purge.size());

            for (const auto& fpath : purge)
                fs::remove(fpath);
        }
    }

    void NodeDB::save_to_disk() const
    {
        if (_root.empty())
            return;

        _router.loop()->call([this]() {
            for (const auto& rc : rc_lookup)
            {
                rc.second.write(get_path_by_pubkey(rc.first));
            }
        });
    }

    bool NodeDB::has_rc(const RemoteRC& rc) const
    {
        return known_rcs.count(rc);
    }

    bool NodeDB::has_rc(const RouterID& pk) const
    {
        return rc_lookup.count(pk);
    }

    std::optional<RemoteRC> NodeDB::get_rc(const RouterID& pk) const
    {
        if (auto itr = rc_lookup.find(pk); itr != rc_lookup.end())
            return itr->second;

        return std::nullopt;
    }

    void NodeDB::remove_router(RouterID pk)
    {
        _router.loop()->call([this, pk]() {
            if (auto itr = rc_lookup.find(pk); itr != rc_lookup.end())
            {}
            rc_lookup.erase(pk);
            remove_many_from_disk_async({pk});
        });
    }

    void NodeDB::remove_stale_rcs()
    {
        auto cutoff_time = time_point_now();

        cutoff_time -= _router.is_service_node() ? RouterContact::OUTDATED_AGE : RouterContact::LIFETIME;

        for (auto itr = rc_lookup.begin(); itr != rc_lookup.end();)
        {
            if (cutoff_time > itr->second.timestamp())
            {
                log::info(logcat, "Pruning RC for {}, as it is too old to keep.", itr->first);
                known_rcs.erase(itr->second);
                itr = rc_lookup.erase(itr);
                continue;
            }
            itr++;
        }
    }

    bool NodeDB::put_rc(RemoteRC rc, rc_time now)
    {
        const auto& rid = rc.router_id();

        if (rid == _router.local_rid())
            return false;

        known_rcs.erase(rc);
        rc_lookup.erase(rid);

        auto [itr, b] = known_rcs.insert(std::move(rc));
        rc_lookup.emplace(rid, *itr);
        known_rids.insert(rid);

        last_rc_update_times[rid] = now;
        return true;
    }

    size_t NodeDB::num_rcs() const
    {
        return known_rcs.size();
    }

    size_t NodeDB::num_rids() const
    {
        return known_rids.size();
    }

    bool NodeDB::verify_store_gossip_rc(const RemoteRC& rc)
    {
        if (registered_routers().count(rc.router_id()))
            return put_rc_if_newer(rc);

        return false;
    }

    void NodeDB::verify_gossip_bfetch_rc(const RemoteRC& rc)
    {
        if (auto maybe = get_rc(rc.router_id()))
        {
            if (maybe->other_is_newer(rc))
                put_rc(rc);
        }
        else
        {
            if (put_rc(rc))
                _router.link_manager().gossip_rc(_router.local_rid(), rc);
        }
    }

    bool NodeDB::put_rc_if_newer(RemoteRC rc)
    {
        if (auto maybe = get_rc(rc.router_id()))
        {
            if (maybe->other_is_newer(rc))
                return put_rc(rc);

            return false;
        }

        return put_rc(rc);
    }

    void NodeDB::remove_many_from_disk_async(std::unordered_set<RouterID> remove) const
    {
        if (_root.empty())
            return;

        // build file list
        std::set<fs::path> files;

        for (auto id : remove)
            files.emplace(get_path_by_pubkey(std::move(id)));

        // remove them from the disk via the diskio thread
        _disk([files]() {
            for (auto fpath : files)
                fs::remove(fpath);
        });
    }

    RemoteRC NodeDB::find_closest_to(llarp::dht::Key_t location) const
    {
        return _router.loop()->call_get([this, location]() -> RemoteRC {
            RemoteRC rc{};
            const llarp::dht::XorMetric compare(location);

            visit_all([&rc, compare](const auto& otherRC) {
                const auto& rid = rc.router_id();

                if (rid.IsZero() || compare(dht::Key_t{otherRC.router_id()}, dht::Key_t{rid}))
                {
                    rc = otherRC;
                    return;
                }
            });
            return rc;
        });
    }

    std::vector<RemoteRC> NodeDB::find_many_closest_to(llarp::dht::Key_t location, uint32_t numRouters) const
    {
        return _router.loop()->call_get([this, location, numRouters]() -> std::vector<RemoteRC> {
            std::vector<const RemoteRC*> all;

            all.reserve(known_rcs.size());

            for (auto& entry : rc_lookup)
            {
                all.push_back(&entry.second);
            }

            auto it_mid = numRouters < all.size() ? all.begin() + numRouters : all.end();

            std::partial_sort(all.begin(), it_mid, all.end(), [compare = dht::XorMetric{location}](auto* a, auto* b) {
                return compare(*a, *b);
            });

            std::vector<RemoteRC> closest;
            closest.reserve(numRouters);
            for (auto it = all.begin(); it != it_mid; ++it)
                closest.push_back(**it);

            return closest;
        });
    }
}  // namespace llarp
