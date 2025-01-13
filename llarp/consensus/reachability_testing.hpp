#pragma once

#include <llarp/contact/router_id.hpp>
#include <llarp/util/time.hpp>

#include <chrono>
#include <queue>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace llarp
{
    struct Router;
}

namespace llarp::consensus
{
    namespace detail
    {
        using clock_t = std::chrono::steady_clock;
        using time_point_t = std::chrono::time_point<clock_t>;

        // Returns std::greater on the std::get<N>(v)th element value.
        template <typename T, size_t N>
        struct nth_greater
        {
            constexpr bool operator()(const T& lhs, const T& rhs) const
            {
                return std::greater<std::tuple_element_t<N, T>>{}(std::get<N>(lhs), std::get<N>(rhs));
            }
        };

        struct incoming_test_state
        {
            time_point_t last_test{};
            time_point_t last_whine{};
            bool was_failing = false;
        };

    }  // namespace detail
    using time_point_t = detail::time_point_t;
    using clock_t = detail::clock_t;

    // How often we tick the timer to check whether we need to do any tests.
    constexpr auto REACHABILITY_TESTING_TIMER_INTERVAL = 50ms;

    class reachability_testing
    {
      public:
        // Distribution for the seconds between node tests: we throw in some randomness to avoid //
        // potential clustering of tests.  (Note that there is some granularity here as the test
        // timer only runs every REACHABILITY_TESTING_TIMER_INTERVAL).
        std::normal_distribution<float> TESTING_INTERVAL{10.0, 3.0};

        // The linear backoff after each consecutive test failure before we re-test.  Specifically
        // we schedule the next re-test for (TESTING_BACKOFF*previous_failures) +
        // TESTING_INTERVAL(rng).
        inline static constexpr auto TESTING_BACKOFF = 10s;

        // The upper bound for the re-test interval.
        inline static constexpr auto TESTING_BACKOFF_MAX = 2min;

        // The maximum number of nodes that we will re-test at once (i.e. per
        // TESTING_TIMING_INTERVAL); mainly intended to throttle ourselves if, for instance, our own
        // connectivity loss makes us accumulate tons of nodes to test all at once.  (Despite the
        // random intervals, this can happen if we also get decommissioned during which we can't
        // test at all but still have lots of failing nodes we want to test right away when we get
        // recommissioned).
        inline static constexpr int MAX_RETESTS_PER_TICK = 4;

        // Maximum time without a ping before we start whining about it.
        //
        // We have a probability of about 0.368* of *not* getting pinged within a ping interval
        // (10s), and so the probability of not getting a ping for 2 minutes (i.e. 12 test spans)
        // just because we haven't been selected is extremely small (0.0000061).  It also coincides
        // nicely with blockchain time (i.e. two minutes) and our max testing backoff.
        //
        // * = approx value of ((n-1)/n)^n for non-tiny values of n
        inline static constexpr auto MAX_TIME_WITHOUT_PING = 2min;

        // How often we whine in the logs about being unreachable
        inline static constexpr auto WHINING_INTERVAL = 2min;

      private:
        // Queue of pubkeys of service nodes to test; we pop off the back of this until the queue
        // empties then we refill it with a shuffled list of all pubkeys then pull off of it until
        // it is empty again, etc.
        std::vector<RouterID> testing_queue;

        // The next time for a general test
        time_point_t next_general_test = time_point_t::min();

        // When we started, so that we know not to hold off on whining about no pings for a while.
        const time_point_t startup = clock_t::now();

        // Pubkeys, next test times, and sequential failure counts of service nodes that are
        // currently in "failed" status along with the last time they failed; we retest them first
        // after 10s then back off linearly by an additional 10s up to a max testing interval of
        // 2m30s, until we get a successful response.
        using FailingPK = std::tuple<RouterID, time_point_t, int>;
        std::priority_queue<FailingPK, std::vector<FailingPK>, detail::nth_greater<FailingPK, 1>> failing_queue;
        std::unordered_set<RouterID> failing;

        // Track the last time *this node* was tested by other network nodes; used to detect and
        // warn about possible network issues.
        detail::incoming_test_state last;

      public:
        // If it is time to perform another random test, this returns the next node to test from the
        // testing queue and returns it, also updating the timer for the next test.  If it is not
        // yet time, or if the queue is empty and cannot current be replenished, returns
        // std::nullopt.  If the queue empties then this builds a new one by shuffling current
        // public keys in the swarm's "all nodes" then starts using the new queue for this an
        // subsequent calls.
        //
        // `requeue` is mainly for internal use: if false it avoids rebuilding the queue if we run
        // out (and instead just return nullopt).
        std::optional<RouterID> next_random(
            Router* router, const time_point_t& now = clock_t::now(), bool requeue = true);

        // Removes and returns up to MAX_RETESTS_PER_TICK nodes that are due to be tested (i.e.
        // next-testing-time <= now).  Returns [snrecord, #previous-failures] for each.
        std::vector<std::pair<RouterID, int>> get_failing(const time_point_t& now = clock_t::now());

        // Adds a bad node pubkey to the failing list, to be re-tested soon (with a backoff
        // depending on `failures`; see TESTING_BACKOFF).  `previous_failures` should be the number
        // of previous failures *before* this one, i.e. 0 for a random general test; or the failure
        // count returned by `get_failing` for repeated failures.
        void add_failing_node(const RouterID& pk, int previous_failures = 0);

        /// removes the public key from the failing set
        void remove_node_from_failing(const RouterID& pk);

        // Called when this router receives an incomming session
        void incoming_ping(const time_point_t& now = clock_t::now());

        // Check whether we received incoming pings recently
        void check_incoming_tests(const time_point_t& now = clock_t::now());
    };

}  // namespace llarp::consensus
