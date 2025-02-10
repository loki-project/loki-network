#pragma once

#include "path_types.hpp"

#include <llarp/address/address.hpp>
#include <llarp/contact/client_intro.hpp>
#include <llarp/util/decaying_hashset.hpp>
#include <llarp/util/thread/threading.hpp>
#include <llarp/util/time.hpp>

#include <atomic>
#include <set>

namespace std
{
    template <>
    struct hash<std::pair<llarp::RouterID, llarp::HopID>>
    {
        size_t operator()(const std::pair<llarp::RouterID, llarp::HopID>& i) const noexcept
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

        // default number of paths per PathHandler
        inline constexpr size_t DEFAULT_PATHS_HELD{4};

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
            static constexpr double THRESHOLD{0.25};

            uint64_t attempts{};
            uint64_t success{};
            uint64_t build_fails{};  // path build failures
            uint64_t path_fails{};   // path failures post-build
            uint64_t timeouts{};

            nlohmann::json ExtractStatus() const;

            double SuccessRatio() const;

            std::string to_string() const;
            static constexpr bool to_string_formattable = true;
        };

        struct PathHandler
        {
            friend struct Path;

          private:
            std::chrono::milliseconds last_warn_time{0s};

            std::unordered_map<RouterID, std::weak_ptr<Path>> path_cache;

            void path_build_backoff();

          protected:
            /// flag for ::Stop()
            std::atomic<bool> _running;

            const size_t num_paths_desired;
            BuildStats _build_stats;

            using Lock_t = util::NullLock;
            mutable util::NullMutex paths_mutex;

            // key: upstream rxid
            std::unordered_map<HopID, std::shared_ptr<Path>> _paths;

            /// return true if we hit our soft limit for building paths too fast on a first hop
            bool build_cooldown_hit(RouterID edge) const;

            void drop_path(const std::shared_ptr<Path>& p);

            virtual void path_died(std::shared_ptr<Path> p);

            virtual void path_build_failed(std::shared_ptr<Path> p, bool timeout = false);

            virtual void path_build_succeeded(std::shared_ptr<Path> p);

          public:
            Router& _router;
            size_t num_hops;
            std::chrono::milliseconds last_build{0s};
            std::chrono::milliseconds build_interval_limit{MIN_PATH_BUILD_INTERVAL};

            std::set<RouterID> snode_blacklist;

            /// construct
            PathHandler(Router& _router, size_t num_paths, size_t num_hops = DEFAULT_LEN);

            virtual ~PathHandler() = default;

            /// get a shared_ptr of ourself
            virtual std::shared_ptr<PathHandler> get_self() = 0;

            /// get a weak_ptr of ourself
            virtual std::weak_ptr<PathHandler> get_weak() = 0;

            /// get the "name" of this path set
            // virtual std::string name() const = 0;

            const Router& router() const { return _router; }

            Router& router() { return _router; }

            virtual void blacklist_snode(const RouterID& remote) { snode_blacklist.insert(remote); }

            std::optional<std::shared_ptr<Path>> get_path(HopID id) const;

            intro_set get_current_client_intros() const;

            nlohmann::json ExtractStatus() const;

            virtual size_t should_build_more() const;

            void expire_paths(std::chrono::milliseconds now);

            void add_path(std::shared_ptr<Path> path);

            std::optional<std::shared_ptr<Path>> get_random_path();

            std::optional<std::shared_ptr<Path>> get_path_conditional(
                std::function<bool(std::shared_ptr<Path>)> filter);

            std::optional<std::unordered_set<std::shared_ptr<Path>>> get_n_random_paths(size_t n, bool exact = false);

            std::optional<std::vector<std::shared_ptr<Path>>> get_n_random_paths_conditional(
                size_t n, std::function<bool(std::shared_ptr<Path>)> filter, bool exact = false);

            /// return true if we hit our soft limit for building paths too fast
            bool build_cooldown() const;

            /// get the number of ACTIVE paths in this status
            size_t num_active_paths() const;

            /// get the number of ALL paths (both active and those being currently build)
            size_t num_paths() const;

            const BuildStats& build_stats() const { return _build_stats; }

            BuildStats& build_stats() { return _build_stats; }

            virtual bool stop(bool send_close = false);

            bool is_stopped() const;

            bool should_remove() const;

            std::chrono::milliseconds now() const;

            virtual void tick(std::chrono::milliseconds now);

            void tick_paths();

            // This method should be overridden by deriving classes
            virtual void build_more(size_t n = 0) = 0;

            bool build_path_to_random();

            bool build_path_aligned_to_remote(const RouterID& remote);

            // TESTNET: testing methods
            // std::optional<std::vector<RemoteRC>> specific_hops_to_remote(std::vector<RouterID> hops);

            std::optional<std::vector<RemoteRC>> aligned_hops_between(const RouterID& edge, const RouterID& pivot);

            std::optional<std::vector<RemoteRC>> aligned_hops_to_remote(
                const RouterID& pivot, const std::set<RouterID>& exclude = {});

            // The build logic is segmented into functions designed to be called sequentially.
            //  - pre_build() : This handles all checking of the vector of hops, verifying with buildlimiter, etc
            //  - build1() : This can be re-implemented by inheriting classes that want to pass different parameters to
            //      the created path. This is useful ßin cases like Outbound Sessions, Paths are constructed with the
            //      respective is_client and is_exit booleans set. Regardless, the implementation needs to return the
            //      created shared_ptr to be passed by reference to build2(...) and build3(...). The implementation MUST
            //      also check if the upstream rxid is already being used for a current path (very unlikely)
            //  - build2() : This contains the bulk of the code that is identical across all instances of path building.
            //      It returns the payload holding the encoded frames for each hop.
            //  - build3() : Inheriting classes can pass their own response handler functions as the second parameter,
            //      allowing for differing lambda captures. This function returns the success/failure of the call to
            //      path::send_control_message(...), allowing for the calling object to decide whether to log path-build
            //      failures for that respective remote or not.
            //  - build() : This function calls pre_build() + build{1,2,3}() in the correct order and is used for the
            //      usual times that PathBuilder initiates a path build
            void build(std::vector<RemoteRC> hops);

            bool pre_build(std::vector<RemoteRC>& hops);

            virtual std::shared_ptr<Path> build1(std::vector<RemoteRC>& hops);

            std::string build2(const std::shared_ptr<Path>& path);

            bool build3(RouterID upstream, std::string payload, std::function<void(oxen::quic::message)> handler);

            void for_each_path(std::function<void(const std::shared_ptr<Path>&)> visit) const;

            /// pick a first hop
            std::optional<RemoteRC> select_first_hop(const std::set<RouterID>& exclude = {}) const;

            virtual std::optional<std::vector<RemoteRC>> get_hops_to_random();
        };
    }  // namespace path

}  // namespace llarp
