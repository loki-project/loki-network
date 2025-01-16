#pragma once

#include "random.hpp"

#include <functional>
#include <optional>

namespace llarp
{
    namespace concepts
    {
        template <typename T, typename U = std::remove_cvref_t<T>>
        concept forward_iterable = std::forward_iterator<typename U::iterator>;

        template <typename T>
        concept scoped_enum =
#ifdef __cpp_lib_scoped_enum
            std::is_scoped_enum_v<T>;
#else
            std::is_enum_v<T> && !std::is_convertible_v<T, std::underlying_type_t<T>>;
#endif
    }  // namespace concepts

    /** Namespace meta:
            Aggregates functional implementations utilized across broadly different contexts.
    */
    namespace meta
    {
        inline namespace enums
        {
            // __cpp_lib_to_underlying is a C++23 feature
            template <typename T, typename U = std::underlying_type_t<std::remove_cv_t<T>>>
                requires std::is_enum_v<T>
            inline constexpr U to_underlying(T e)
            {
                return static_cast<U>(e);
            }
        }  // namespace enums

        /** Aggregated generalized algorithms for sort, selection, etc
         */
        inline namespace sampling
        {
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
        }  // namespace sampling

    }  // namespace meta

}  // namespace llarp
