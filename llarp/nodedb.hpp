#pragma once

#include "contact/relay_contact.hpp"
#include "contact/router_id.hpp"
#include "crypto/crypto.hpp"
#include "router/router.hpp"
#include "util/common.hpp"
#include "util/thread/threading.hpp"

#include <algorithm>
#include <atomic>
#include <map>
#include <optional>
#include <set>
#include <unordered_set>
#include <utility>

namespace llarp
{
    struct Router;

    // TESTNET: the following constants have been shortened for testing purposes

    inline constexpr auto FETCH_INTERVAL{10min};
    inline constexpr auto PURGE_INTERVAL{5min};
    inline constexpr auto FLUSH_INTERVAL{5min};

    /*  RC Fetch Constants  */
    // fallback to bootstrap if we have less than this many RCs
    inline constexpr size_t MIN_ACTIVE_RCS{6};
    // max number of attempts we make in non-bootstrap fetch requests
    inline constexpr int MAX_FETCH_ATTEMPTS{10};
    // the total number of returned rcs that are held locally should be at least this
    inline constexpr size_t MIN_GOOD_RC_FETCH_TOTAL{};
    // the ratio of returned rcs found locally to to total returned should be above this ratio
    inline constexpr double MIN_GOOD_RC_FETCH_THRESHOLD{};

    /*  RID Fetch Constants  */
    // the number of rid sources that we make rid fetch requests to
    inline constexpr size_t RID_SOURCE_COUNT{8};
    // upper limit on how many rid fetch requests to rid sources can fail
    inline constexpr int MAX_RID_ERRORS{2};
    // each returned rid must appear this number of times across all responses
    inline constexpr int MIN_RID_FETCH_FREQ{6};  //  TESTNET:
    // the total number of accepted returned rids should be above this number
    inline constexpr size_t MIN_GOOD_RID_FETCH_TOTAL{};
    // the ratio of accepted:rejected rids must be above this ratio
    inline constexpr double GOOD_RID_FETCH_THRESHOLD{};

    /*  Bootstrap Constants  */
    // the number of rc's we query the bootstrap for; service nodes pass 0, which means
    // gimme all dat RCs
    inline constexpr size_t SERVICE_NODE_BOOTSTRAP_SOURCE_COUNT{0};
    inline constexpr size_t CLIENT_BOOTSTRAP_SOURCE_COUNT{10};

    // if all bootstraps fail, router will trigger re-bootstrapping after this cooldown
    inline constexpr auto FETCH_ATTEMPT_INTERVAL{15s};
    inline constexpr auto FETCH_ATTEMPTS{1};

    /*  Other Constants  */
    // the maximum number of RC/RID fetches that can pass w/o an unconfirmed rc/rid appearing
    inline constexpr int MAX_CONFIRMATION_ATTEMPTS{5};
    // threshold amount of verifications to promote an unconfirmed rc/rid
    inline constexpr int CONFIRMATION_THRESHOLD{3};

    template <
        typename ID_t,
        std::enable_if_t<std::is_same_v<ID_t, RouterID> || std::is_same_v<ID_t, RemoteRC>, int> = 0>
    struct Unconfirmed
    {
        const ID_t id;
        int attempts = 0;
        int verifications = 0;

        Unconfirmed() = delete;
        Unconfirmed(const ID_t& obj) : id{obj} {}
        Unconfirmed(ID_t&& obj) : id{std::move(obj)} {}

        int strikes() const { return attempts; }

        operator bool() const { return verifications == CONFIRMATION_THRESHOLD; }

        bool operator==(const Unconfirmed& other) const { return id == other.id; }

        bool operator<(const Unconfirmed& other) const { return id < other.id; }
    };

    using rc_set = std::set<RemoteRC, XorMetric>;

    class NodeDB
    {
        friend struct Router;

        Router& _router;
        const fs::path _root;

        bool _is_service_node{false};

        /******** RouterID/RelayContacts ********/

        using Lock_t = util::NullLock;
        mutable util::NullMutex nodedb_mutex;

        /** RouterID mappings
            Both the following are populated in NodeDB startup with RouterID's stored on disk.
            - known_rids: meant to persist between lokinet sessions, and is only
              populated during startup and RouterID fetching. This is meant to represent the
              client instance's most recent perspective of the network, and record which RouterID's
              were recently "active" and connected to
            - unconfirmed_rids: holds new rids returned in fetch requests to be verified by
           subsequent fetch requests
            - known_rcs: populated during startup and when RC's are updated both during gossip
              and periodic RC fetching
            - unconfirmed_rcs: holds new rcs to be verified by subsequent fetch requests, similar to
              the unknown_rids container
            - rc_lookup: holds all the same rc's as known_rcs, but can be used to look them up by
              their rid
            - bootstrap_seeds: if we are the seed node, we insert the rc's of bootstrap fetch
           requests senders into this container to "introduce" them to each other
            - _bootstraps: the standard container for bootstrap RemoteRCs
        */
        std::set<RouterID> known_rids;
        std::set<Unconfirmed<RouterID>> unconfirmed_rids;

        std::set<RemoteRC> known_rcs;
        std::set<Unconfirmed<RemoteRC>> unconfirmed_rcs;

        std::unordered_map<RouterID, RemoteRC> rc_lookup;

        BootstrapList _bootstraps{};

        // All registered relays (service nodes)
        std::set<RouterID> _registered_routers;

        // if populated from a config file, lists specific exclusively used as path first-hops
        std::set<RouterID> _pinned_edges;

        // if true, ONLY use pinned edges for first hop
        bool _strict_connect{false};

        // source of "truth" for RC updating. This relay will also mediate requests to the
        // 8 selected active RID's for RID fetching
        RouterID fetch_source;
        // set of 8 randomly selected RID's from the client's set of routers
        std::set<RouterID> rid_sources{};
        // logs the RID's that resulted in an error during RID fetching
        std::set<RouterID> fail_sources{};
        // tracks the number of times each rid appears in the above responses
        std::unordered_map<RouterID, std::atomic<int>> rid_result_counters{};

        std::atomic<int> fetch_counter{};
        std::atomic<int> fail_counter{};
        std::atomic<int> response_counter{};

        template <std::invocable Callable>
        void _disk_hook(Callable&& f) const
        {
            _router.queue_disk_io(std::forward<Callable>(f));
        }

        // Returns true iff the RID is known, but not the RC
        bool want_rc(const RouterID& rid) const;

        /// asynchronously remove the files for a set of rcs on disk given their public ident key
        void remove_many_from_disk_async(std::unordered_set<RouterID> idents) const;

        /// get filename of an RC file given its public ident key
        fs::path get_path_by_pubkey(const RouterID& pk) const;

        void _ensure_skiplist(fs::path nodedbDir);

        // TESTNET: NEW MEMBERS FOR BOOTSTRAPPING MANAGED BY EVENTTRIGGER OBJECT
        std::atomic<bool> _needs_bootstrap{false}, _is_bootstrapping{false}, _has_bstrap_connection{false},
            _is_connecting_bstrap{false};

        std::shared_ptr<EventTrigger> _bootstrap_handler;

        std::shared_ptr<EventTicker> _rid_fetch_ticker;
        std::shared_ptr<EventTicker> _rc_fetch_ticker;

        std::shared_ptr<EventTicker> _purge_ticker;
        std::shared_ptr<EventTicker> _flush_ticker;

      public:
        static std::shared_ptr<NodeDB> make(fs::path rootdir, Router* r)
        {
            return std::make_shared<NodeDB>(std::move(rootdir), r);
        }

        explicit NodeDB(fs::path rootdir, Router* r) : _router{*r}, _root{std::move(rootdir)}
        {
            _ensure_skiplist(_root);
            rid_result_counters.clear();
        }

        bool strict_connect_enabled() const { return _strict_connect; }

        void start_tickers();

        void configure();

        // returns {num_rcs, num_rids, num_bootstraps}
        std::tuple<size_t, size_t, size_t> db_stats() const;

        const std::set<RouterID>& get_known_rids() const { return known_rids; }

        const std::set<RemoteRC>& get_known_rcs() const { return known_rcs; }

        std::optional<RemoteRC> get_rc_by_rid(const RouterID& rid);

        void process_fetched_rcs(std::set<RemoteRC> rcs);

        void ingest_fetched_rids(const RouterID& source, std::optional<std::set<RouterID>> ids = std::nullopt);

        void process_fetched_rids();

        std::vector<RouterID> get_expired_rcs();

        // TESTNET: new bootstrap/initial fetch functions
        void fetch_rcs();
        void fetch_rids();
        void bootstrap();

        void post_rid_fetch(bool shutdown = false);
        void post_rc_fetch(bool shutdown = false);

        void rid_fetch_result();
        void rc_fetch_result(std::optional<std::set<RemoteRC>> result = std::nullopt);
        void stop_bootstrap(bool success = true);
        bool is_bootstrapping() const { return _is_bootstrapping; }
        bool needs_bootstrap() const { return _needs_bootstrap; }
        bool bootstrap_completed() const { return not(_is_bootstrapping or _needs_bootstrap); }
        bool is_bootstrap_node(const RemoteRC& rc) const;
        void purge_rcs(std::chrono::milliseconds now = llarp::time_now_ms());

        // Populate rid_sources with random sample from known_rids. A set of rids is passed
        // if only specific RID's need to be re-selected; to re-select all, pass the member
        // variable ::known_rids
        void reselect_router_id_sources(std::set<RouterID> specific);

        void set_router_whitelist(const std::vector<RouterID>& whitelist);

        std::optional<RouterID> get_random_registered_router() const;

        // client:
        //   if pinned edges were specified, connections are allowed only to those and
        //   to the configured bootstrap nodes.  otherwise, always allow.
        //
        // relay:
        //   outgoing connections are allowed only to other registered, funded relays
        //   (whitelist and greylist, respectively).
        bool is_connection_allowed(const RouterID& remote) const;

        // client:
        //   same as is_connection_allowed
        //
        // server:
        //   we only build new paths through registered, not decommissioned relays
        //   (i.e. whitelist)
        bool is_path_allowed(const RouterID& remote) const { return known_rids.count(remote); }

        // if pinned edges were specified, the remote must be in that set, else any remote
        // is allowed as first hop.
        bool is_first_hop_allowed(const RouterID& remote) const;

        std::set<RouterID>& pinned_edges() { return _pinned_edges; }

        void bootstrap_init();

        size_t num_bootstraps() const { return _bootstraps.size(); }

        bool has_bootstraps() const { return _bootstraps.empty(); }

        const BootstrapList& bootstrap_list() const { return _bootstraps; }

        BootstrapList& bootstrap_list() { return _bootstraps; }

        void set_bootstrap_routers(BootstrapList& from_router);

        std::set<RouterID>& registered_routers() { return _registered_routers; }

        const std::set<RouterID>& registered_routers() const { return _registered_routers; }

        const std::set<RemoteRC>& get_rcs() const { return known_rcs; }

        /// load all known_rcs from disk syncrhonously
        void load_from_disk();

        /// explicit save all RCs to disk synchronously
        void save_to_disk() const;

        /// called on close
        void cleanup();

        /// the number of known RC's currently held
        size_t num_rcs() const;

        size_t num_rids() const;

        /// do periodic tasks like flush to disk and expiration
        bool tick(std::chrono::milliseconds now);

        /// find the absolute closets router to a dht location
        RemoteRC find_closest_to(hash_key location) const;

        /// find many routers closest to dht key; if num_routers = 0, return ALL routers
        rc_set find_many_closest_to(hash_key location, uint32_t num_routers = 0) const;

        /// return true if we have an rc by its ident pubkey
        bool has_rc(const RouterID& pk) const;

        bool has_rc(const RemoteRC& rc) const;

        /// maybe get an rc by its ident pubkey
        std::optional<RemoteRC> get_rc(const RouterID& pk) const;

        std::optional<std::vector<RemoteRC>> get_random_rc() const;

        // Get `n` random RCs from all RCs we know about.  If `exact` is true then we require n
        // matches (and otherwise return nullopt); otherwise we return whatever we found, or nullopt
        // if we find nothing at all.
        std::optional<std::vector<RemoteRC>> get_n_random_rcs(size_t n, bool exact = false) const;

        /** The following random conditional functions utilize a simple implementation of reservoir
            sampling to return either 1 or n random RC's using only one pass through the set of
            RC's.

            Pseudocode:
              - begin iterating through the set
                - load the first n (or 1) that pass hook(n) into a list Selected[]
                - for all that pass the hook, increment i, tracking the number seen thus far
                - generate a random integer x from 0 to i
                  - x < n ? Selected[x] = current : continue;
        */
        std::optional<RemoteRC> get_random_rc_conditional(std::function<bool(RemoteRC)> hook) const;

        std::optional<std::vector<RemoteRC>> get_n_random_rcs_conditional(
            size_t n, std::function<bool(RemoteRC)> hook, bool exact = false, bool use_strict_connect = false) const;

        /// put (or replace) the RC if we consider it valid (want_rc).  returns true if put.
        bool put_rc(RemoteRC rc);

        /// if we consider it valid (want_rc),
        /// put this rc into the cache if it is not there or is newer than the one there already
        /// returns true if the rc was inserted
        bool put_rc_if_newer(RemoteRC rc);

        bool verify_store_gossip_rc(const RemoteRC& rc);

      private:
        // Updates `current` to not contain any of the elements of `replace` and resamples (up to
        // `target_size`) from population to refill it.
        template <typename T, typename RNG>
        void replace_subset(
            std::set<T>& current, const std::set<T>& replace, std::set<T> population, size_t target_size, RNG&& rng)
        {
            for (auto it = replace.begin(); it != replace.end(); ++it)
            {
                // Remove the ones we are replacing from current:
                current.erase(*it);
                // Remove from the population to not reselect
                population.erase(*it);
            }

            for (auto it = current.begin(); it != current.end(); ++it)
                population.erase(*it);

            if (current.size() < target_size)
                std::sample(
                    population.begin(),
                    population.end(),
                    std::inserter(current, current.end()),
                    target_size - current.size(),
                    rng);
        }

        /// remove an entry given a filter that inspects the rc
        template <typename Filter>
        void remove_if(Filter visit)
        {
            // only called from within event loop ticker
            assert(_router.loop()->in_event_loop());

            std::unordered_set<RouterID> removed;

            for (auto itr = rc_lookup.begin(); itr != rc_lookup.end();)
            {
                if (visit(itr->second))
                {
                    removed.insert(itr->first);
                    known_rids.erase(itr->first);
                    known_rcs.erase(itr->second);
                    itr = rc_lookup.erase(itr);
                }
                else
                    ++itr;
            }

            if (not removed.empty())
                remove_many_from_disk_async(std::move(removed));
        }

        template <
            typename ID_t,
            std::enable_if_t<std::is_same_v<ID_t, RouterID> || std::is_same_v<ID_t, RemoteRC>, int> = 0>
        void process_results(std::set<ID_t> unconfirmed, std::set<Unconfirmed<ID_t>>& container, std::set<ID_t>& known)
        {
            // before we add the unconfirmed set, we check to see if our local set of unconfirmed
            // rcs/rids appeared in the latest unconfirmed set; if so, we will increment their
            // number of verifications and reset the attempts counter. Once appearing in 3 different
            // requests, the rc/rid will be "verified" and promoted to the known_{rcs,rids}
            // container
            for (auto itr = container.begin(); itr != container.end();)
            {
                auto& id = itr->id;
                auto& count = const_cast<int&>(itr->attempts);
                auto& verifications = const_cast<int&>(itr->verifications);

                if (auto found = unconfirmed.find(id); found != unconfirmed.end())
                {
                    if (++verifications >= CONFIRMATION_THRESHOLD)
                    {
                        if constexpr (std::is_same_v<ID_t, RemoteRC>)
                            put_rc_if_newer(id);
                        else
                            known.emplace(id);
                        itr = container.erase(itr);
                    }
                    else
                    {
                        // reset attempt counter and continue
                        count = 0;
                        ++itr;
                    }

                    unconfirmed.erase(found);
                }

                itr = (++count >= MAX_CONFIRMATION_ATTEMPTS) ? container.erase(itr) : ++itr;
            }

            for (auto& id : unconfirmed)
            {
                container.emplace(std::move(id));
            }
        }
    };
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::Unconfirmed<llarp::RemoteRC>> : public hash<llarp::RemoteRC>
    {};

    template <>
    struct hash<llarp::Unconfirmed<llarp::RouterID>> : hash<llarp::RouterID>
    {};
}  // namespace std
