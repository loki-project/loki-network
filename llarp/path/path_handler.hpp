#pragma once

#include "path_types.hpp"

#include <llarp/router_id.hpp>
#include <llarp/service/intro.hpp>
#include <llarp/util/decaying_hashset.hpp>
#include <llarp/util/thread/threading.hpp>
#include <llarp/util/time.hpp>
#include <llarp/util/types.hpp>

#include <atomic>
#include <set>

namespace std
{
    template <>
    struct hash<std::pair<llarp::RouterID, llarp::HopID>>
    {
        size_t operator()(const std::pair<llarp::RouterID, llarp::HopID>& i) const
        {
            return hash<llarp::RouterID>{}(i.first) ^ hash<llarp::HopID>{}(i.second);
        }
    };
}  // namespace std

namespace llarp
{
    struct Router;

    namespace path
    {
        // maximum number of paths a path-set can maintain
        inline constexpr size_t MAX_PATHS{32};

        // forward declare
        struct Path;

        /// limiter for path builds
        /// prevents overload and such
        class BuildLimiter
        {
            util::DecayingHashSet<RouterID> _edge_limiter;

          public:
            /// attempt a build
            /// return true if we are allowed to continue
            bool Attempt(const RouterID& router);

            /// decay limit entries
            void Decay(std::chrono::milliseconds now);

            /// return true if this router is currently limited
            bool Limited(const RouterID& router) const;
        };

        /// Stats about all our path builds
        struct BuildStats
        {
            static constexpr double MinGoodRatio = 0.25;

            uint64_t attempts = 0;
            uint64_t success = 0;
            uint64_t build_fails = 0;  // path build failures
            uint64_t path_fails = 0;   // path failures post-build
            uint64_t timeouts = 0;

            StatusObject ExtractStatus() const;

            double SuccessRatio() const;

            std::string to_string() const;
        };

        /// TODO: supplant the PathRole int typedef with this, potentially make these ints rather
        /// bitshifted values. This would require redoing the PathRole logic, where roles
        /// can be stacked with |=
        ///
        /// TODO: is a path role even necessary?
        enum class Path_Role
        {
            ANY = 0,
            EXIT = 1 << 1,
            CLIENTSVC = 1 << 2,
            SERVERSVC = 1 << 3
        };

        struct PathHandler
        {
          private:
            std::chrono::milliseconds last_warn_time = 0s;

            std::unordered_map<RouterID, std::weak_ptr<Path>> path_cache;

            void path_build_backoff();

            void associate_hop_ids(std::shared_ptr<Path> p);

          protected:
            void dissociate_hop_ids(std::shared_ptr<Path> p);

            /// flag for ::Stop()
            std::atomic<bool> _running;

            size_t num_paths_desired;
            BuildStats _build_stats;

            using Mtx_t = util::NullMutex;
            using Lock_t = util::NullLock;
            mutable Mtx_t paths_mutex;

            // TODO: make into templated map object
            std::unordered_map<HopID, RouterID> _path_lookup;
            std::unordered_map<RouterID, std::shared_ptr<Path>> _paths;

            /// return true if we hit our soft limit for building paths too fast on a first hop
            bool build_cooldown_hit(RouterID edge) const;

            void drop_path(const RouterID& remote);

            virtual void path_died(std::shared_ptr<Path> p);

            void path_build_failed(const RouterID& remote, std::shared_ptr<Path> p, bool timeout = false);

            virtual void path_build_succeeded(const RouterID& remote, std::shared_ptr<Path> p);

          public:
            Router& _router;
            size_t num_hops;
            std::chrono::milliseconds _last_build = 0s;
            std::chrono::milliseconds build_interval_limit = MIN_PATH_BUILD_INTERVAL;

            std::set<RouterID> snode_blacklist;

            /// construct
            PathHandler(Router& _router, size_t num_paths, size_t num_hops = DEFAULT_LEN);

            virtual ~PathHandler() = default;

            /// get a shared_ptr of ourself
            virtual std::shared_ptr<PathHandler> get_self() = 0;

            /// get a weak_ptr of ourself
            virtual std::weak_ptr<PathHandler> get_weak() = 0;

            /// get the "name" of this path set
            virtual std::string name() const = 0;

            const Router& router() const
            {
                return _router;
            }

            Router& router()
            {
                return _router;
            }

            virtual void blacklist_snode(const RouterID& remote)
            {
                snode_blacklist.insert(remote);
            }

            std::optional<std::shared_ptr<Path>> get_path(HopID id) const;

            std::optional<std::shared_ptr<Path>> get_path(const RouterID& router) const;

            std::optional<std::set<service::Introduction>> get_path_intros_conditional(
                std::function<bool(const service::Introduction&)> filter) const;

            StatusObject ExtractStatus() const;

            virtual bool should_build_more() const;

            void expire_paths(std::chrono::milliseconds now);

            void add_path(std::shared_ptr<Path> path);

            void add_path(const RouterID& remote, std::shared_ptr<Path> path);

            std::optional<std::shared_ptr<Path>> get_random_path();

            std::optional<std::shared_ptr<Path>> get_path_conditional(
                std::function<bool(std::shared_ptr<Path>)> filter);

            std::optional<std::unordered_set<std::shared_ptr<Path>>> get_n_random_paths(size_t n, bool exact = false);

            std::optional<std::vector<std::shared_ptr<Path>>> get_n_random_paths_conditional(
                size_t n, std::function<bool(std::shared_ptr<Path>)> filter, bool exact = false);

            /// count the number of paths that will exist at this timestamp in future
            size_t paths_at_time(std::chrono::milliseconds futureTime) const;

            virtual void reset_path_state();

            /// return true if we hit our soft limit for building paths too fast
            bool build_cooldown() const;

            /// get the number of paths in this status
            size_t num_paths() const;

            const BuildStats& build_stats() const
            {
                return _build_stats;
            }

            BuildStats& build_stats()
            {
                return _build_stats;
            }

            virtual bool stop(bool send_close = false);

            bool is_stopped() const;

            bool should_remove() const;

            std::chrono::milliseconds now() const;

            virtual void Tick(std::chrono::milliseconds now);

            void tick_paths();

            // This method should be overridden by deriving classes
            virtual void build_more(size_t n = 0) = 0;

            bool build_path_to_random();

            bool build_path_aligned_to_remote(const RouterID& remote);

            std::optional<std::vector<RemoteRC>> aligned_hops_to_remote(
                const RouterID& endpoint, const std::set<RouterID>& exclude = {});

            // The build logic is segmented into functions designed to be called sequentially.
            //  - build1() : This can be re-implemented by inheriting classes that want to pass off possession of the
            //      newly created Path object, rather than emplacing it within its internal path mapping. This is useful
            //      in cases like session initiation, where RemoteHandler wants to hand off the newly created path to
            //      the OutboundSession object. Regardless, the implementation needs to return the created shared_ptr to
            //      be passed by reference to build2(...) and build3(...).
            //  - build2() : This contains the bulk of the code that is identical across all instances of path building.
            //      It returns the payload holding the encoded frames for each hop.
            //  - build3() : Inheriting classes can pass their own response handler functions as the second parameter,
            //      allowing for differing lambda captures. This function returns the success/failure of the call to
            //      path::send_control_message(...), allowing for the calling object to decide whether to log path-build
            //      failures for that respective remote or not
            std::shared_ptr<Path> build1(std::vector<RemoteRC>& hops);

            std::string build2(std::shared_ptr<Path>& path);

            bool build3(
                std::shared_ptr<Path>& path, std::string payload, std::function<void(oxen::quic::message)> handler);

            void build(std::vector<RemoteRC> hops);

            void for_each_path(std::function<void(const std::shared_ptr<Path>&)> visit) const;

            /// pick a first hop
            std::optional<RemoteRC> select_first_hop(const std::set<RouterID>& exclude = {}) const;

            virtual std::optional<std::vector<RemoteRC>> get_hops_to_random();
        };
    }  // namespace path

}  // namespace llarp
