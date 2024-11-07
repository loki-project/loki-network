#pragma once

#include "concept.hpp"
#include "random.hpp"

#include <functional>
#include <optional>

namespace llarp::meta
{
    /** Aggregated generalized algorithms for sort, selection, etc
     */

    /** One-pass random selection algorithm
        - https://en.wikipedia.org/wiki/Reservoir_sampling
    */
    template <concepts::forward_iterable T, typename R = std::remove_cvref_t<T>::value_type>
    std::optional<R> sample(const T& container, std::function<bool(R)> hook)
    {
        size_t i = 0;
        std::optional<R> ret = std::nullopt;

        for (const auto& e : container)
        {
            if (not hook(e))
                continue;

            if (++i <= 1)
            {
                ret = e;
                continue;
            }

            size_t x = csrng() % (i + 1);
            if (x <= 1)
                ret = e;
        }

        return ret;
    }

    template <concepts::forward_iterable T, typename R = std::remove_cvref_t<T>::value_type>
    std::optional<std::vector<R>> sample_n(
        const T& container, std::function<bool(R)> hook, size_t n, bool exact = false)
    {
        auto ret = std::make_optional<std::vector<R>>();
        ret->reserve(n);

        size_t i = 0;

        for (const auto& e : container)
        {
            if (not hook(e))
                continue;

            if (++i <= n)
            {
                ret->emplace_back(e);
                continue;
            }

            size_t x = csrng() % (i + 1);
            if (x < n)
                (*ret)[x] = e;
        }

        if (ret->size() < (exact ? n : 1))
            ret.reset();

        return ret;
    }
}  // namespace llarp::meta
