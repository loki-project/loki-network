#include "nodedb.hpp"

#include "crypto/types.hpp"
#include "dht/kademlia.hpp"
#include "link/link_manager.hpp"
#include "messages/fetch.hpp"
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

        size_t i = 0;
        std::optional<RemoteRC> res = std::nullopt;

        for (const auto& rc : known_rcs)
        {
            if (not hook(rc))
                continue;

            if (++i <= 1)
            {
                res = rc;
                continue;
            }

            size_t x = csrng() % (i + 1);
            if (x <= 1)
                res = rc;
        }

        return res;
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

    bool NodeDB::tick(std::chrono::milliseconds now)
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
                _bootstrap_handler->begin();
            }

            return false;
        }

        purge_rcs(now);
        return true;
    }

    void NodeDB::purge_rcs(std::chrono::milliseconds now)
    {
        remove_if([&](const RemoteRC& rc) -> bool {
            // don't purge bootstrap nodes from nodedb
            if (is_bootstrap_node(rc.router_id()))
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
            if (not _router.whitelist_received)
            {
                log::debug(logcat, "Skipping check on {}: don't have whitelist yet", rc.router_id());
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

    bool NodeDB::want_rc(const RouterID& rid) const
    {
        if (not _is_service_node)
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
        return _router.loop()->call_get([&]() {
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

            log::info(
                logcat,
                "Num received: {}, confirmed (intersection) size: {}, fetch_threshold: {}",
                num_received,
                inter_size,
                fetch_threshold);

            /** We are checking 2 things here:
                1) The number of "good" rcs is above MIN_GOOD_RC_FETCH_TOTAL
                2) The ratio of "good" rcs to total received is above MIN_GOOD_RC_FETCH_THRESHOLD
            */
            bool success = false;
            if (success = (inter_size >= MIN_GOOD_RC_FETCH_TOTAL) and (fetch_threshold >= MIN_GOOD_RC_FETCH_THRESHOLD);
                success)
            {
                // set rcs to be intersection set
                rcs = std::move(confirmed_set);
                process_results(std::move(unconfirmed_set), unconfirmed_rcs, known_rcs);
            }

            return success;
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
    bool NodeDB::process_fetched_rids()
    {
        return _router.loop()->call_get([this]() {
            std::set<RouterID> union_set, confirmed_set, unconfirmed_set;

            for (const auto& [rid, count] : rid_result_counters)
            {
                log::info(logcat, "RID: {}, Freq: {}", rid.ShortString(), count);
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
            const auto num_received = (double)(rid_result_counters.size() - fetch_counter);
            // the total number of received AND accepted rids
            const auto union_size = union_set.size();

            const auto fetch_threshold = (double)union_size / num_received;

            bool success = (fetch_threshold >= GOOD_RID_FETCH_THRESHOLD) and (union_size >= MIN_GOOD_RID_FETCH_TOTAL);

            log::info(
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
                process_results(std::move(unconfirmed_set), unconfirmed_rids, known_rids);
                known_rids.merge(confirmed_set);
            }

            return success;
        });
    }

    void NodeDB::ingest_fetched_rids(const RouterID& source, std::optional<std::set<RouterID>> rids)
    {
        if (rids)
        {
            for (const auto& rid : *rids)
                rid_result_counters[rid] += 1;
        }
        else
            fail_sources.insert(source);
    }

    std::vector<RouterID> NodeDB::get_expired_rcs()
    {
        return _router.loop()->call_get([this]() {
            std::vector<RouterID> needed;
            const auto now = time_point_now();

            for (const auto& [rid, rc] : rc_lookup)
            {
                if (now - rc.timestamp() > RelayContact::OUTDATED_AGE)
                    needed.push_back(rid);
            }

            return needed;
        });
    }

    void NodeDB::fetch_rcs()
    {
        if (_router._is_stopping || not _router._is_running)
        {
            log::info(logcat, "NodeDB unable to continue RC fetch -- router is stopped!");
            return stop_rc_fetch(false);
        }

        std::vector<RouterID> needed = get_expired_rcs();

        auto& src = fetch_source;
        log::info(logcat, "Dispatching FetchRC's request to {} for {} RCs!", src, needed.size());

        _router.link_manager()->fetch_rcs(
            src, FetchRCMessage::serialize(needed), [this, source = src](oxen::quic::message m) mutable {
                if (not m)
                {
                    log::critical(
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

                        {
                            auto btlc = btdc.require<oxenc::bt_list_consumer>("rcs"sv);

                            while (not btlc.is_finished())
                                rcs.emplace(btlc.consume_dict_data());
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
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        if (result)
        {
            log::info(logcat, "RC fetching was successful; processing {} returned RCs...", result->size());

            if (process_fetched_rcs(*result))
            {
                log::info(logcat, "Accumulated RID's accepted by trust model");
                return stop_rc_fetch(true);
            }

            log::warning(logcat, "Accumulated RC's rejected by trust model; reselecting RC fetch source...");
        }
        else
        {
            log::warning(logcat, "RC fetching was unsuccessful; reselecting RC fetch source...");
        }

        fetch_source = *std::next(known_rids.begin(), csrng() % known_rids.size());
    }

    void NodeDB::fetch_rids()
    {
        if (_router._is_stopping || not _router._is_running)
        {
            log::info(logcat, "NodeDB unable to continue RouterID fetch -- router is stopped!");
            return stop_rid_fetch(false);
        }

        if (rid_sources.empty())
        {
            log::debug(logcat, "Client reselecting RID sources...");
            reselect_router_id_sources(rid_sources);
        }

        fetch_counter = 0;
        rid_result_counters.clear();

        do
            fetch_source = *std::next(known_rids.begin(), csrng() % known_rids.size());
        while (rid_sources.contains(fetch_source));

        auto& src = fetch_source;

        // TESTNET:
        // rid_sources.emplace(oxenc::from_base32z("55fxrrdt9ggkra9yoi58gbespa13is1sqqrykdzjamgkxrq91tto"));
        // auto& src = _bootstraps.current().router_id();

        for (const auto& target : rid_sources)
        {
            if (target == src)
                continue;

            log::info(logcat, "Sending FetchRIDs request to {} via {}", target, src);
            _router.link_manager()->fetch_router_ids(
                src,
                FetchRIDMessage::serialize(target),
                [this, source = src, target = target](oxen::quic::message m) mutable {
                    if (not m)
                    {
                        log::critical(
                            logcat,
                            "RID fetch from {} via {} {}",
                            target,
                            source,
                            m.timed_out ? "timed out" : "failed: {}"_format(m.view()));
                        ingest_fetched_rids(target);
                    }
                    else
                    {
                        try
                        {
                            std::set<RouterID> router_ids;
                            oxenc::bt_dict_consumer btdc{m.body()};

                            {
                                auto btlc = btdc.require<oxenc::bt_list_consumer>("routers");

                                while (not btlc.is_finished())
                                    router_ids.emplace(btlc.consume_string_view());
                            }

                            btdc.require_signature("signature", [&target](ustring_view msg, ustring_view sig) {
                                if (sig.size() != 64)
                                    throw std::runtime_error{"Invalid signature: not 64 bytes"};
                                if (not crypto::verify(target, msg, sig))
                                    throw std::runtime_error{
                                        "Failed to verify signature for fetch RouterIDs response."};
                            });

                            ingest_fetched_rids(target, std::move(router_ids));
                        }
                        catch (const std::exception& e)
                        {
                            log::critical(logcat, "Error handling fetch RouterIDs response: {}", e.what());
                            ingest_fetched_rids(target);
                        }
                    }

                    rid_fetch_result(source);
                });

            fetch_counter += 1;
        }
    }

    void NodeDB::rid_fetch_result(const RouterID& via)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        size_t n_fails = fail_sources.size();
        int n_responses = rid_result_counters[via];

        if (n_responses < fetch_counter)
        {
            log::info(logcat, "Received {}/{} fetch RID requests", n_responses, fetch_counter);
            return;
        }

        log::info(logcat, "Received {}/{} fetch RID requests! Processing...", n_responses, fetch_counter);

        if (n_fails <= MAX_RID_ERRORS)
        {
            log::info(logcat, "RID fetching was successful ({}/{} acceptable errors)", n_fails, MAX_RID_ERRORS);

            // this is where the trust model will do verification based on the similarity of the sets
            if (process_fetched_rids())
            {
                log::info(logcat, "Accumulated RID's accepted by trust model");
                return stop_rid_fetch(true);
            }

            log::warning(logcat, "Accumulated RID's rejected by trust model; reselecting RID fetch sources...");
        }
        else
        {
            // we had 4 or more failed requests, so we will need to rotate our rid sources
            log::critical(logcat, "RID fetching found {} failures; reselecting failed RID fetch sources...", n_fails);
        }

        reselect_router_id_sources(fail_sources);
    }

    bool NodeDB::is_bootstrap_node(RouterID rid) const
    {
        return has_bootstraps() ? _bootstraps.contains(rid) : false;
    }

    void NodeDB::start_tickers()
    {
        log::debug(logcat, "NodeDB starting flush ticker...");

        _flush_ticker = _router.loop()->call_every(FLUSH_INTERVAL, [this]() {
            log::debug(logcat, "Writing NodeDB contents to disk...");
            save_to_disk();
        });

        if (not _is_service_node)
        {
            // start these immediately if we do not need to bootstrap
            _rid_fetch_ticker = _router.loop()->call_every(
                FETCH_INTERVAL, [this]() { fetch_rids(); }, not _needs_bootstrap);
            _rc_fetch_ticker = _router.loop()->call_every(
                FETCH_INTERVAL, [this]() { fetch_rcs(); }, not _needs_bootstrap);
        }
    }

    void NodeDB::configure()
    {
        _is_service_node = _router._is_service_node;

        bootstrap_init();
        load_from_disk();

        _needs_bootstrap = num_rcs() < MIN_ACTIVE_RCS;
    }

    void NodeDB::stop_rc_fetch(bool success)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _rc_fetch_ticker->stop();

        if (success)
            log::info(logcat, "Client successfully completed RelayContact fetch!");
        else
            log::warning(logcat, "Client stopped RelayContact fetch without a sucessful response!");
    }

    void NodeDB::stop_rid_fetch(bool success)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        fetch_counter = 0;
        fail_sources.clear();
        rid_result_counters.clear();
        _rid_fetch_ticker->stop();

        if (success)
            log::info(logcat, "Client successfully completed RouterID fetch!");
        else
            log::warning(logcat, "Client stopped RouterID fetch without a sucessful response!");
    }

    void NodeDB::stop_bootstrap(bool success)
    {
        _is_bootstrapping = false;
        // this function is only called in success or lokinet shutdown, so we will never need bootstrapping
        _needs_bootstrap = false;
        _bootstrap_handler->halt();

        if (success)
        {
            log::info(logcat, "{} completed processing BootstrapRC fetch!", _is_service_node ? "Relay" : "Client");

            if (not _is_service_node)
            {
                if (not _rid_fetch_ticker->is_running())
                {
                    log::debug(logcat, "Client starting RID fetch ticker");
                    _rid_fetch_ticker->start();
                }

                if (not _rc_fetch_ticker->is_running())
                {
                    log::debug(logcat, "Client starting RC fetch ticker");
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
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_router._is_stopping || not _router._is_running)
        {
            log::info(logcat, "NodeDB unable to continue bootstrap fetch -- router is stopped!");
            return stop_bootstrap(false);
        }

        auto rc = _is_bootstrapping.exchange(true) ? _bootstraps.next() : _bootstraps.current();
        auto source = rc.router_id();

        log::info(logcat, "Dispatching BootstrapRC to {}", source);

        auto num_needed = _is_service_node ? SERVICE_NODE_BOOTSTRAP_SOURCE_COUNT : CLIENT_BOOTSTRAP_SOURCE_COUNT;

        _router.link_manager()->fetch_bootstrap_rcs(
            rc,
            BootstrapFetchMessage::serialize(
                _is_service_node ? std::make_optional(_router.relay_contact) : std::nullopt, num_needed),
            [this, src = source](oxen::quic::message m) mutable {
                log::info(logcat, "Received response to BootstrapRC fetch request...");

                if (not m)
                {
                    log::warning(logcat, "BootstrapRC fetch request to {} failed", src);
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
                            put_rc(RemoteRC{btlc.consume_dict_data()});
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
                    log::critical(
                        logcat,
                        "{} BootstrapRC fetch successfully produced {} RCs ({} minimum needed)",
                        _is_service_node ? "Relay" : "Client",
                        num,
                        MIN_ACTIVE_RCS);
                    return stop_bootstrap(/* true */);
                }

                log::info(
                    logcat,
                    "BootstrapRC response from {} returned {} RCs ({} minimum needed); continuing bootstrapping...",
                    src,
                    num,
                    MIN_ACTIVE_RCS);
            });
    }

    bool NodeDB::reselect_router_id_sources(std::set<RouterID> specific)
    {
        return _router.loop()->call_get([&]() {
            replace_subset(rid_sources, specific, known_rids, RID_SOURCE_COUNT, csrng);

            if (auto sz = rid_sources.size(); sz < RID_SOURCE_COUNT)
            {
                log::warning(logcat, "Insufficient RID's (count: {}) held locally for fetching!", sz);
                return false;
            }

            return true;
        });
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
        if (not _is_service_node)
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

    void NodeDB::bootstrap_init()
    {
        log::debug(logcat, "NodeDB storing bootstraps...");

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

        log::debug(logcat, "NodeDB creating bootstrap event handler...");

        _bootstrap_handler = EventTrigger::make(
            _router.loop(), FETCH_ATTEMPT_INTERVAL, [this]() { bootstrap(); }, FETCH_ATTEMPTS);
    }

    void NodeDB::load_from_disk()
    {
        Lock_t l{nodedb_mutex};

        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

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
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_root.empty())
            return;

        _router.loop()->call([this]() {
            for (const auto& rc : known_rcs)
                rc.write(get_path_by_pubkey(rc.router_id()));
        });
    }

    void NodeDB::cleanup()
    {
        if (_bootstrap_handler)
        {
            log::debug(logcat, "NodeDB clearing bootstrap handler...");
            _bootstrap_handler->halt();
            _bootstrap_handler.reset();
        }

        if (_rid_fetch_ticker)
        {
            log::debug(logcat, "NodeDB clearing rid fetch ticker...");
            _rid_fetch_ticker->stop();
            _rid_fetch_ticker.reset();
        }

        if (_rc_fetch_ticker)
        {
            log::debug(logcat, "NodeDB clearing rc fetch ticker...");
            _rc_fetch_ticker->stop();
            _rc_fetch_ticker.reset();
        }

        if (_flush_ticker)
        {
            log::debug(logcat, "NodeDB clearing flush ticker...");
            _flush_ticker->stop();
            _flush_ticker.reset();
        }
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

    void NodeDB::remove_stale_rcs()
    {
        auto cutoff_time = time_point_now();

        cutoff_time -= _is_service_node ? RelayContact::OUTDATED_AGE : RelayContact::LIFETIME;

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

    bool NodeDB::put_rc(RemoteRC rc)
    {
        Lock_t l{nodedb_mutex};

        bool ret{true};
        const auto& rid = rc.router_id();

        if (rid == _router.local_rid())
            return false;

        known_rcs.erase(rc);
        rc_lookup.erase(rid);

        auto [itr, b] = known_rcs.insert(std::move(rc));
        ret &= b;
        ret &= rc_lookup.emplace(rid, *itr).second;
        ret &= known_rids.insert(rid).second;

        return ret;
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

    bool NodeDB::put_rc_if_newer(RemoteRC rc)
    {
        if (auto maybe = get_rc(rc.router_id()))
        {
            if (not maybe->other_is_newer(rc))
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
        _disk_hook([files]() {
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

                if (rid.is_zero() || compare(dht::Key_t{otherRC.router_id()}, dht::Key_t{rid}))
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
