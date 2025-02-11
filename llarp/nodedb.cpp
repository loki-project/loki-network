#include "nodedb.hpp"

#include "crypto/types.hpp"
#include "link/link_manager.hpp"
#include "messages/fetch.hpp"
#include "util/meta.hpp"
#include "util/time.hpp"

#include <algorithm>
#include <unordered_map>
#include <utility>

namespace llarp
{
    static auto logcat = llarp::log::Cat("nodedb");

    static constexpr auto RC_FILE_EXT = ".signed"sv;

    void NodeDB::_ensure_skiplist(fs::path nodedbDir)
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

    std::tuple<size_t, size_t, size_t> NodeDB::db_stats() const { return {num_rcs(), num_rids(), num_bootstraps()}; }

    std::optional<RemoteRC> NodeDB::get_rc_by_rid(const RouterID& rid)
    {
        if (auto itr = rc_lookup.find(rid); itr != rc_lookup.end())
            return itr->second;

        return std::nullopt;
    }

    std::optional<std::vector<RemoteRC>> NodeDB::get_random_rc() const
    {
        auto rand = std::make_optional<std::vector<RemoteRC>>();

        std::sample(known_rcs.begin(), known_rcs.end(), std::back_inserter(*rand), 1, csrng);
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
        std::optional<std::vector<RemoteRC>> rand = get_random_rc();

        if (rand.has_value())
        {
            if (auto& rc = rand->front(); hook(rc))
                return rc;
        }

        return meta::sample(known_rcs, std::move(hook));
    }

    std::optional<std::vector<RemoteRC>> NodeDB::get_n_random_rcs_conditional(
        size_t n, std::function<bool(RemoteRC)> hook, bool exact, bool /* use_strict_connect */) const
    {
        return meta::sample_n(known_rcs, std::move(hook), n, exact);
    }

    bool NodeDB::tick([[maybe_unused]] std::chrono::milliseconds now)
    {
        if (_is_bootstrapping or _is_connecting_bstrap)
        {
            log::trace(logcat, "NodeDB deferring ::tick() to bootstrap fetch completion...");
            return false;
        }

        // only enter bootstrap process if we have NOT marked initial fetch as needed
        if (_needs_bootstrap and not _router.is_bootstrap_seed())
        {
            if (not _has_bstrap_connection)
            {
                if (_is_connecting_bstrap)
                {
                    log::trace(logcat, "{} awaiting bstrap connect attempt...", _is_service_node ? "Relay" : "Client");
                    return false;
                }

                auto& brc = _bootstraps.current();
                auto bsrc = brc.router_id();

                log::critical(
                    logcat,
                    "{} has 0 router connections; connecting to bootstrap {}...",
                    _is_service_node ? "Relay" : "Client",
                    bsrc);

                _router.link_manager()->connect_to(
                    brc,
                    [this](oxen::quic::connection_interface& ci) {
                        log::critical(logcat, "Successfully connected to bootstrap node!");
                        _has_bstrap_connection = true;
                        _is_connecting_bstrap = false;
                        return _router.link_manager()->on_conn_open(ci);
                    },
                    [this](oxen::quic::connection_interface& ci, uint64_t ec) {
                        log::critical(logcat, "Failed to connect to bootstrap node!");
                        _is_connecting_bstrap = false;
                        return _router.link_manager()->on_conn_closed(ci, ec);
                    });

                _is_connecting_bstrap = true;
                return false;
            }

            if (not _bootstrap_handler->is_iterating())
            {
                log::critical(
                    logcat,
                    "{} has {} of {} minimum RCs; initiating BootstrapRC fetch...",
                    _is_service_node ? "Relay" : "Client",
                    num_rcs(),
                    MIN_ACTIVE_RCS);
                _bootstrap_handler->start();
            }

            return false;
        }

        return true;
    }

    void NodeDB::purge_rcs(std::chrono::milliseconds now)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "NodeDB unable to continue purge ticking -- router is stopped!");
            return;
        }

        remove_if([&](const RemoteRC& rc) -> bool {
            // don't purge bootstrap nodes from nodedb
            if (is_bootstrap_node(rc))
            {
                log::trace(logcat, "Not removing {}: is bootstrap node", rc.router_id());
                return false;
            }

            // if for some reason we stored an RC that isn't a valid router
            // purge this entry
            if (not rc.is_public_addressable())
            {
                log::debug(logcat, "Removing {}: not a valid router", rc.router_id());
                return true;
            }

            // clear out a fully expired RC
            if (rc.is_expired(now))
            {
                log::debug(logcat, "Removing {}: RC is expired", rc.router_id());
                return true;
            }

            // clients have no notion of a whilelist
            // we short circuit logic here so we dont remove
            // routers that are not whitelisted for first hops
            if (not _is_service_node)
            {
                log::trace(logcat, "Not removing {}: we are a client and it looks fine", rc.router_id());
                return false;
            }

            // if we don't have the whitelist yet don't remove the entry
            if (not _router.has_whitelist())
            {
                log::trace(logcat, "Skipping check on {}: don't have whitelist yet", rc.router_id());
                return false;
            }

            // if we have no whitelist enabled or we have
            // the whitelist enabled and we got the whitelist
            // check against the whitelist and remove if it's not
            // in the whitelist OR if there is no whitelist don't remove
            if (not is_connection_allowed(rc.router_id()))
            {
                log::debug(logcat, "Removing {}: not a valid router", rc.router_id());
                return true;
            }

            return false;
        });

        _needs_bootstrap = num_rcs() < MIN_ACTIVE_RCS;
    }

    fs::path NodeDB::get_path_by_pubkey(const RouterID& pubkey) const
    {
        return "{}/{}{}"_format(_root.c_str(), pubkey.to_string(), RC_FILE_EXT);
    }

    bool NodeDB::want_rc(const RouterID& rid) const { return known_rids.count(rid) and not rc_lookup.contains(rid); }

    void NodeDB::set_bootstrap_routers(BootstrapList& from_router)
    {
        _bootstraps.merge(from_router);
        _bootstraps.randomize();
    }

    void NodeDB::process_fetched_rcs(std::set<RemoteRC> rcs)
    {
        _router.loop()->call([&]() {
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

            log::trace(
                logcat,
                "Num received: {}, confirmed (intersection) size: {}, fetch_threshold: {}",
                num_received,
                inter_size,
                fetch_threshold);

            /** We are checking 2 things here:
                1) The number of "good" rcs is above MIN_GOOD_RC_FETCH_TOTAL
                2) The ratio of "good" rcs to total received is above MIN_GOOD_RC_FETCH_THRESHOLD
            */
            bool success = (inter_size >= MIN_GOOD_RC_FETCH_TOTAL) and (fetch_threshold >= MIN_GOOD_RC_FETCH_THRESHOLD);

            if (success)
            {
                log::debug(logcat, "Accumulated RC's accepted by trust model");
                rcs = std::move(confirmed_set);
                process_results(std::move(unconfirmed_set), unconfirmed_rcs, known_rcs);
                post_rc_fetch(false);
            }
            else
            {
                log::warning(logcat, "Accumulated RC's rejected by trust model; reselecting RC fetch source...");
                cycle_fetch_source();
            }
        });
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
    void NodeDB::process_fetched_rids()
    {
        _router.loop()->call([&]() {
            std::set<RouterID> union_set, confirmed_set, unconfirmed_set;

            for (const auto& [rid, count] : rid_result_counters)
            {
                log::trace(logcat, "RID: {}, Freq: {}", rid.ShortString(), count);
                if (count >= MIN_RID_FETCH_FREQ)
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
            const auto num_received = (double)(rid_result_counters.size());
            // the total number of received AND accepted rids
            const auto union_size = union_set.size();

            const auto fetch_threshold = (double)union_size / num_received;

            bool success = (fetch_threshold >= GOOD_RID_FETCH_THRESHOLD) and (union_size >= MIN_GOOD_RID_FETCH_TOTAL);

            log::trace(
                logcat,
                "Num received: {}, union size: {}, known rid size: {}, fetch_threshold: {}, status: {}",
                num_received,
                union_size,
                known_rids.size(),
                fetch_threshold,
                success ? "SUCCESS" : "FAIL");

            /** We are checking 2 things here:
                1) The ratio of received/accepted to total received is above GOOD_RID_FETCH_THRESHOLD.
                This tells us how well the rid source's sets of rids "agree" with one another
                2) The total number received is above MIN_RID_FETCH_TOTAL. This ensures that we are
                receiving a sufficient amount to make a comparison of any sorts
            */
            if (success)
            {
                log::debug(logcat, "Accumulated RID's accepted by trust model");
                process_results(std::move(unconfirmed_set), unconfirmed_rids, known_rids);
                known_rids.merge(confirmed_set);
                post_rid_fetch(false);
            }
            else
            {
                log::warning(logcat, "Accumulated RID's rejected by trust model; reselecting RID fetch sources...");
                reselect_router_id_sources(fail_sources);
            }
        });
    }

    void NodeDB::ingest_fetched_rids(const RouterID& source, std::optional<std::set<RouterID>> rids)
    {
        log::debug(logcat, "Ingesting {} RID's from {}", rids ? rids->size() : 0, source);

        if (rids)
        {
            for (const auto& rid : *rids)
                rid_result_counters[rid] += 1;
        }
        else
        {
            fail_sources.insert(source);
            fail_counter += 1;
            log::trace(logcat, "{} marked as a failed fetch source (currently: {})", source, fail_counter);
        }

        rid_fetch_result();
    }

    std::vector<RouterID> NodeDB::get_expired_rcs()
    {
        return _router.loop()->call_get([this]() {
            std::vector<RouterID> needed;

            for (const auto& [rid, rc] : rc_lookup)
            {
                if (rc.is_outdated())
                    needed.push_back(rid);
            }

            return needed;
        });
    }

    void NodeDB::fetch_rcs()
    {
        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "NodeDB unable to continue RC fetch -- router is stopped!");
            return post_rc_fetch(true);
        }

        std::vector<RouterID> needed = get_expired_rcs();

        cycle_fetch_source();
        auto& src = fetch_source;
        log::debug(logcat, "Dispatching FetchRC's request to {} for {} RCs!", src, needed.size());

        _router.link_manager()->fetch_rcs(
            src, FetchRCMessage::serialize(needed), [this, source = src](oxen::quic::message m) mutable {
                if (not m)
                {
                    log::info(
                        logcat,
                        "RC fetch from {} {}",
                        source,
                        m.timed_out ? "timed out" : "failed: {}"_format(m.view()));
                }
                else
                {
                    try
                    {
                        std::set<RemoteRC> rcs;
                        oxenc::bt_dict_consumer btdc{m.body()};

                        btdc.required("r");

                        {
                            auto sublist = btdc.consume_list_consumer();

                            while (not sublist.is_finished())
                                rcs.emplace(sublist.consume_dict_data());
                        }

                        return rc_fetch_result(std::move(rcs));
                    }
                    catch (const std::exception& e)
                    {
                        log::critical(logcat, "Failed to parse RC fetch response from {}: {}", source, e.what());
                    }
                }

                rc_fetch_result();
            });
    }

    void NodeDB::rc_fetch_result(std::optional<std::set<RemoteRC>> result)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (result)
        {
            log::info(logcat, "RC fetching was successful; processing {} returned RCs...", result->size());
            return process_fetched_rcs(std::move(*result));
        }

        log::warning(logcat, "RC fetching was unsuccessful; reselecting RC fetch source...");
        fetch_source = *std::next(known_rids.begin(), csrng.boundedrand(known_rids.size()));
    }

    void NodeDB::fetch_rids()
    {
        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "NodeDB unable to continue RouterID fetch -- router is stopped!");
            return post_rid_fetch(true);
        }

        if (rid_sources.empty())
        {
            log::debug(logcat, "Client reselecting RID sources...");
            reselect_router_id_sources(rid_sources);
        }

        fetch_counter = 0;
        response_counter = 0;
        fail_counter = 0;
        fail_sources.clear();
        rid_result_counters.clear();

        do
            fetch_source = *std::next(known_rids.begin(), csrng.boundedrand(known_rids.size()));
        while (rid_sources.contains(fetch_source));

        auto& src = fetch_source;

        for (const auto& target : rid_sources)
        {
            if (target == src)
                continue;

            log::trace(logcat, "Sending FetchRIDs request to {} via {}", target, src);
            _router.link_manager()->fetch_router_ids(
                src,
                FetchRIDMessage::serialize(target),
                [this, source = src, target = target](oxen::quic::message m) mutable {
                    response_counter += 1;
                    if (not m)
                    {
                        log::info(
                            logcat,
                            "RID fetch from {} via {} {}",
                            target,
                            source,
                            m.timed_out ? "timed out" : "failed: {}"_format(m.view()));
                        ingest_fetched_rids(source);
                    }
                    else
                    {
                        try
                        {
                            std::set<RouterID> router_ids;
                            oxenc::bt_dict_consumer btdc{m.body()};

                            btdc.required("r");

                            {
                                auto sublist = btdc.consume_list_consumer();

                                while (not sublist.is_finished())
                                    router_ids.emplace(sublist.consume_string_view());
                            }

                            btdc.require_signature("~", [&target](ustring_view msg, ustring_view sig) {
                                if (sig.size() != 64)
                                    throw std::runtime_error{"Invalid signature: not 64 bytes"};
                                if (not crypto::verify(target, msg, sig))
                                    throw std::runtime_error{
                                        "Failed to verify signature for fetch RouterIDs response."};
                            });

                            ingest_fetched_rids(source, std::move(router_ids));
                        }
                        catch (const std::exception& e)
                        {
                            log::critical(logcat, "Error handling fetch RouterIDs response: {}", e.what());
                            ingest_fetched_rids(source);
                        }
                    }
                });

            fetch_counter += 1;
        }
    }

    void NodeDB::rid_fetch_result()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        int n_fails = fail_counter.load();
        int n_responses = response_counter.load();

        if (n_responses < fetch_counter)
        {
            log::trace(logcat, "Received {}/{} fetch RID requests", n_responses, fetch_counter);
            return;
        }

        log::trace(logcat, "Received {}/{} fetch RID requests! Processing...", n_responses, fetch_counter);

        if (n_fails <= MAX_RID_ERRORS)
        {
            log::info(logcat, "RID fetching was successful ({}/{} acceptable errors)", n_fails, MAX_RID_ERRORS);
            return process_fetched_rids();
        }

        log::critical(logcat, "RID fetching found {} failures; reselecting failed RID fetch sources...", n_fails);
        reselect_router_id_sources(fail_sources);
    }

    bool NodeDB::is_bootstrap_node(const RemoteRC& rc) const
    {
        return has_bootstraps() ? _bootstraps.contains(rc) : false;
    }

    void NodeDB::start_tickers()
    {
        log::trace(logcat, "NodeDB starting tickers...");

        _flush_ticker = _router.loop()->call_every(FLUSH_INTERVAL, [this]() mutable { save_to_disk(); });
        _router.loop()->call_later(approximate_time(5s, 5), [&]() { save_to_disk(); });

        _purge_ticker = _router.loop()->call_every(
            PURGE_INTERVAL, [this]() mutable { purge_rcs(); }, not _needs_bootstrap);
        if (not _needs_bootstrap)
            _router.loop()->call_later(approximate_time(10s, 10), [&]() { purge_rcs(); });

        if (not _is_service_node)
        {
            // start these immediately if we do not need to bootstrap
            _rc_fetch_ticker = _router.loop()->call_every(
                FETCH_INTERVAL, [this]() mutable { fetch_rcs(); }, not _needs_bootstrap);

            _rid_fetch_ticker = _router.loop()->call_every(
                FETCH_INTERVAL, [this]() mutable { fetch_rids(); }, not _needs_bootstrap);

            if (not _needs_bootstrap)
            {
                _router.loop()->call_later(approximate_time(5s, 5), [&]() { fetch_rcs(); });
                _router.loop()->call_later(approximate_time(10s, 5), [&]() { fetch_rids(); });
            }
        }
    }

    void NodeDB::configure()
    {
        _is_service_node = _router.is_service_node();

        bootstrap_init();
        load_from_disk();

        _needs_bootstrap = num_rcs() < MIN_ACTIVE_RCS;
    }

    void NodeDB::post_rc_fetch(bool shutdown)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (shutdown)
        {
            _rc_fetch_ticker->stop();
            log::warning(logcat, "Client stopped RelayContact fetch without a sucessful response!");
        }
        else
            log::debug(logcat, "Client successfully completed RC fetching!");
    }

    void NodeDB::post_rid_fetch(bool shutdown)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        fetch_counter = 0;
        response_counter = 0;
        fail_counter = 0;
        fail_sources.clear();
        rid_result_counters.clear();

        if (shutdown)
        {
            _rid_fetch_ticker->stop();
            log::warning(logcat, "Client stopped RouterID fetch without a sucessful response!");
        }
        else
            log::debug(logcat, "Client successfully completed RouterID fetch!");
    }

    void NodeDB::stop_bootstrap(bool success)
    {
        _is_bootstrapping = false;
        // this function is only called in success or lokinet shutdown, so we will never need bootstrapping
        _needs_bootstrap = false;
        _bootstrap_handler->stop();

        if (success)
        {
            log::debug(logcat, "{} completed processing BootstrapRC fetch!", _is_service_node ? "Relay" : "Client");

            if (not _purge_ticker->is_running())
            {
                log::trace(logcat, "{} activating NodeDB purge ticker", _is_service_node ? "Relay" : "Client");
                _purge_ticker->start();
            }

            if (not _is_service_node)
            {
                if (not _rid_fetch_ticker->is_running())
                {
                    log::trace(logcat, "Client starting RID fetch ticker");
                    _rid_fetch_ticker->start();
                }

                if (not _rc_fetch_ticker->is_running())
                {
                    log::trace(logcat, "Client starting RC fetch ticker");
                    _rc_fetch_ticker->start();
                }
            }
        }
        else
            log::critical(
                logcat, "{} stopping bootstrap without a successful fetch!", _is_service_node ? "Relay" : "Client");
    }

    void NodeDB::bootstrap()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "NodeDB unable to continue bootstrap fetch -- router is stopped!");
            return stop_bootstrap(false);
        }

        auto rc = _is_bootstrapping.exchange(true) ? _bootstraps.next() : _bootstraps.current();
        auto source = rc.router_id();

        log::debug(logcat, "Dispatching BootstrapRC to {}", source);

        auto num_needed = _is_service_node ? SERVICE_NODE_BOOTSTRAP_SOURCE_COUNT : CLIENT_BOOTSTRAP_SOURCE_COUNT;

        _router.link_manager()->fetch_bootstrap_rcs(
            rc,
            BootstrapFetchMessage::serialize(
                _is_service_node ? std::make_optional(_router.rc()) : std::nullopt, num_needed),
            [this, src = source](oxen::quic::message m) mutable {
                log::debug(logcat, "Received response to BootstrapRC fetch request...");

                if (not m)
                {
                    log::warning(logcat, "BootstrapRC fetch request to {} failed", src);
                    return;
                }

                size_t num = 0, accepted = 0;

                try
                {
                    oxenc::bt_dict_consumer btdc{m.body()};

                    btdc.required("r");

                    {
                        auto sublist = btdc.consume_list_consumer();

                        while (not sublist.is_finished())
                        {
                            accepted += put_rc(RemoteRC{sublist.consume_dict_data()});
                            ++num;
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Failed to parse BootstrapRC fetch response from {}: {}", src, e.what());
                    return;
                }

                if (num >= MIN_ACTIVE_RCS)
                {
                    log::info(
                        logcat,
                        "{} BootstrapRC fetch successfully produced {} RCs ({} minimum needed) with {} accepted",
                        _is_service_node ? "Relay" : "Client",
                        num,
                        MIN_ACTIVE_RCS,
                        accepted);
                    return stop_bootstrap(/* true */);
                }

                log::warning(
                    logcat,
                    "BootstrapRC response from {} returned {} RCs ({} minimum needed); continuing bootstrapping...",
                    src,
                    num,
                    MIN_ACTIVE_RCS);
            });
    }

    void NodeDB::reselect_router_id_sources(std::set<RouterID> specific)
    {
        replace_subset(rid_sources, specific, known_rids, RID_SOURCE_COUNT, csrng);

        if (auto sz = rid_sources.size(); sz < RID_SOURCE_COUNT)
        {
            log::warning(logcat, "Insufficient RID's (count: {}) held locally for fetching!", sz);
        }
    }

    void NodeDB::set_router_whitelist(const std::vector<RouterID>& whitelist)
    {
        log::critical(logcat, "Oxend provided {} whitelisted routers", whitelist.size());

        if (whitelist.empty())
            return;

        _registered_routers.clear();
        _registered_routers.insert(whitelist.begin(), whitelist.end());

        log::critical(
            logcat, "Service node holding {} registered relays after oxend integration", _registered_routers.size());
    }

    std::optional<RouterID> NodeDB::get_random_registered_router() const
    {
        std::function<bool(RouterID)> hook = [](const auto&) -> bool { return true; };
        return meta::sample(_registered_routers, hook);
    }

    bool NodeDB::is_connection_allowed(const RouterID& remote) const
    {
        if (not _is_service_node)
        {
            if (_pinned_edges.size() && _pinned_edges.count(remote) == 0 && not _bootstraps.contains(remote))
                return false;

            return known_rids.count(remote);
        }

        return known_rids.count(remote) and _registered_routers.empty() ? true : _registered_routers.count(remote);
    }

    bool NodeDB::is_first_hop_allowed(const RouterID& remote) const
    {
        if (_pinned_edges.size() && _pinned_edges.count(remote) == 0)
            return false;

        return true;
    }

    void NodeDB::bootstrap_init()
    {
        log::trace(logcat, "NodeDB storing bootstraps...");

        if (_bootstraps.empty())
            return;

        size_t counter{0};

        for (const auto& rc : _bootstraps)
            counter += put_rc(rc);

        auto bsz = _bootstraps.size();
        auto success = counter == bsz;
        auto msg = "NodeDB {}successfully stored {}/{} bootstrap routers"_format(success ? "" : "un", counter, bsz);

        if (success)
            log::debug(logcat, "{}", msg);
        else
            log::critical(logcat, "{}", msg);

        log::trace(logcat, "NodeDB creating bootstrap event handler...");

        _bootstrap_handler = EventTrigger::make(
            _router.loop(), FETCH_ATTEMPT_INTERVAL, [this]() { bootstrap(); }, FETCH_ATTEMPTS);
    }

    void NodeDB::load_from_disk()
    {
        Lock_t l{nodedb_mutex};

        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

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
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_root.empty())
            return;

        log::debug(logcat, "Writing NodeDB contents to disk...");

        for (const auto& rc : known_rcs)
            rc.write(get_path_by_pubkey(rc.router_id()));
    }

    void NodeDB::cleanup()
    {
        if (_bootstrap_handler)
        {
            log::trace(logcat, "NodeDB clearing bootstrap handler...");
            _bootstrap_handler->stop();
            _bootstrap_handler.reset();
        }

        if (_rid_fetch_ticker)
        {
            log::trace(logcat, "NodeDB clearing rid fetch ticker...");
            _rid_fetch_ticker->stop();
            _rid_fetch_ticker.reset();
        }

        if (_rc_fetch_ticker)
        {
            log::trace(logcat, "NodeDB clearing RC fetch ticker...");
            _rc_fetch_ticker->stop();
            _rc_fetch_ticker.reset();
        }

        if (_purge_ticker)
        {
            log::trace(logcat, "NodeDB clearing purge ticker...");
            _purge_ticker->stop();
            _purge_ticker.reset();
        }

        if (_flush_ticker)
        {
            log::trace(logcat, "NodeDB clearing flush ticker...");
            _flush_ticker->stop();
            _flush_ticker.reset();
        }

        log::debug(logcat, "NodeDB cleared all tickers...");
    }

    bool NodeDB::has_rc(const RemoteRC& rc) const { return known_rcs.count(rc); }

    bool NodeDB::has_rc(const RouterID& pk) const { return rc_lookup.count(pk); }

    std::optional<RemoteRC> NodeDB::get_rc(const RouterID& pk) const
    {
        if (auto itr = rc_lookup.find(pk); itr != rc_lookup.end())
            return itr->second;

        return std::nullopt;
    }

    bool NodeDB::put_rc(RemoteRC rc)
    {
        Lock_t l{nodedb_mutex};

        bool ret{true};
        const auto& rid = rc.router_id();

        if (rid == _router.local_rid())
            return false;

        // Use the rc_lookup RemoteRC to delete from known_rcs, as the differing timestamp between the old and new will
        // result in set::insert not matching to the previous value
        if (auto it = rc_lookup.find(rid); it != rc_lookup.end())
        {
            known_rcs.erase(it->second);
            rc_lookup.erase(it);
        }
        else
        {
            known_rcs.erase(rc);
            rc_lookup.erase(rid);
        }

        auto [itr, b] = known_rcs.insert(std::move(rc));
        ret &= b;
        ret &= rc_lookup.emplace(rid, *itr).second;
        ret &= known_rids.insert(rid).second;

        return ret;
    }

    size_t NodeDB::num_rcs() const { return known_rcs.size(); }

    size_t NodeDB::num_rids() const { return known_rids.size(); }

    void NodeDB::cycle_fetch_source()
    {
        fetch_source = *std::next(known_rids.begin(), csrng.boundedrand(known_rids.size()));
        log::debug(logcat, "New fetch source is {}", fetch_source);
    }

    bool NodeDB::verify_store_gossip_rc(const RemoteRC& rc)
    {
        if (registered_routers().count(rc.router_id()))
            return put_rc_if_newer(rc);

        return false;
    }

    bool NodeDB::put_rc_if_newer(RemoteRC rc)
    {
        if (auto maybe = get_rc(rc.router_id()))
        {
            if (not maybe->other_is_newer(rc))
                return false;
        }

        put_rc(std::move(rc));
        return true;
    }

    void NodeDB::remove_many_from_disk_async(std::unordered_set<RouterID> remove) const
    {
        if (_root.empty())
            return;

        // build file list
        std::set<fs::path> files;

        for (auto it = remove.begin(); it != remove.end(); it = remove.erase(it))
            files.emplace(get_path_by_pubkey(std::move(*it)));

        // remove them from the disk via the diskio thread
        _disk_hook([files = std::move(files)]() {
            for (auto fpath : files)
                fs::remove(fpath);
        });
    }

    RemoteRC NodeDB::find_closest_to(llarp::hash_key location) const
    {
        return _router.loop()->call_get([this, compare = XorMetric{location}]() -> RemoteRC {
            return *std::ranges::min_element(known_rcs, compare);
        });
    }

    rc_set NodeDB::find_many_closest_to(llarp::hash_key location, uint32_t num_routers) const
    {
        return _router.loop()->call_get([this, compare = XorMetric{location}, num_routers]() -> rc_set {
            rc_set ret{known_rcs.begin(), known_rcs.end(), compare};
            if (num_routers)
                ret.erase(std::next(ret.begin(), num_routers), ret.end());
            return ret;
        });
    }
}  // namespace llarp
