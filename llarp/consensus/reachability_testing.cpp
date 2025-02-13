
#include "reachability_testing.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging.hpp>

using std::chrono::steady_clock;

namespace llarp::consensus
{
    static auto logcat = log::Cat("reachability");

    using fseconds = std::chrono::duration<float, std::chrono::seconds::period>;
    using fminutes = std::chrono::duration<float, std::chrono::minutes::period>;

    static void check_incoming_tests_impl(
        std::string_view name,
        const time_point_t& now,
        const time_point_t& startup,
        detail::incoming_test_state& incoming)
    {
        const auto elapsed = now - std::max(startup, incoming.last_test);
        bool failing = elapsed > reachability_testing::MAX_TIME_WITHOUT_PING;
        bool whine = failing != incoming.was_failing
            || (failing && now - incoming.last_whine > reachability_testing::WHINING_INTERVAL);

        incoming.was_failing = failing;

        if (whine)
        {
            incoming.last_whine = now;
            if (!failing)
            {
                log::info(logcat, "{} received ping; port is likely reachable!", name);
            }
            else
            {
                if (incoming.last_test.time_since_epoch() == 0s)
                {
                    log::warning(logcat, "{} has NEVER received pings!", name);
                }
                else
                {
                    log::warning(
                        logcat, "Have not received pings from {} in {} minutes", name, fminutes{elapsed}.count());
                }

                log::warning(logcat, "Check {} port. Non-reachabibility may result in deregistration!", name);
            }
        }
    }

    void reachability_testing::check_incoming_tests(const time_point_t& now)
    {
        check_incoming_tests_impl("lokinet", now, startup, last);
    }

    void reachability_testing::incoming_ping(const time_point_t& now) { last.last_test = now; }

    std::optional<RouterID> reachability_testing::next_random(Router* router, const time_point_t& now, bool requeue)
    {
        if (next_general_test > now)
            return std::nullopt;
        next_general_test =
            now + std::chrono::duration_cast<time_point_t::duration>(fseconds(TESTING_INTERVAL(llarp::csrng)));

        // Pull the next element off the queue, but skip ourself, any that are no longer registered,
        // and any that are currently known to be failing (those are queued for testing separately).
        auto local_pk = router->local_rid();

        while (!testing_queue.empty())
        {
            auto& pk = testing_queue.back();
            std::optional<RouterID> sn;

            if (pk != local_pk && !failing.count(pk))
                sn = pk;

            testing_queue.pop_back();

            if (sn)
                return sn;
        }

        if (!requeue)
            return std::nullopt;

        // FIXME: when a *new* node comes online we need to inject it into a random position in the
        // SN list with probability (L/N) [L = current list size, N = potential list size]
        //

        // We exhausted the queue so repopulate it and try again

        testing_queue.clear();
        const auto& all = router->get_whitelist();

        testing_queue.insert(testing_queue.begin(), all.begin(), all.end());

        std::shuffle(testing_queue.begin(), testing_queue.end(), llarp::csrng);

        // Recurse with the rebuilt list, but don't let it try rebuilding again
        return next_random(router, now, false);
    }

    std::vector<std::pair<RouterID, int>> reachability_testing::get_failing(const time_point_t& now)
    {
        // Our failing_queue puts the oldest retest times at the top, so pop them off into our
        // result until the top node should be retested sometime in the future
        std::vector<std::pair<RouterID, int>> result;
        while (result.size() < MAX_RETESTS_PER_TICK && !failing_queue.empty())
        {
            auto& [pk, retest_time, failures] = failing_queue.top();
            if (retest_time > now)
                break;
            if (failing.count(pk))
                result.emplace_back(pk, failures);
            failing_queue.pop();
        }
        return result;
    }

    void reachability_testing::add_failing_node(const RouterID& pk, int previous_failures)
    {
        using namespace std::chrono;

        if (previous_failures < 0)
            previous_failures = 0;
        auto next_test_in = duration_cast<time_point_t::duration>(
            previous_failures * TESTING_BACKOFF + fseconds{TESTING_INTERVAL(llarp::csrng)});
        if (next_test_in > TESTING_BACKOFF_MAX)
            next_test_in = TESTING_BACKOFF_MAX;

        failing.insert(pk);
        failing_queue.emplace(pk, steady_clock::now() + next_test_in, previous_failures + 1);
    }

    void reachability_testing::remove_node_from_failing(const RouterID& pk) { failing.erase(pk); }

}  // namespace llarp::consensus
