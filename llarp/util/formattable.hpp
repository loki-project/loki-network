#pragma once

// #include <oxen/log/format.hpp>

#include <fmt/format.h>
#include <oxen/quic/format.hpp>

#include <type_traits>

// Formattable types can specialize this to true and will get automatic fmt formattering support via
// their .to_string() method.

namespace llarp
{
    // Types can opt-in to being fmt-formattable by ensuring they have a ::to_string() method defined
    template <typename T>
    concept
#if (!(defined(__clang__)) && defined(__GNUC__) && __GNUC__ < 10)
        bool
#endif
            ToStringFormattable = oxen::quic::ToStringFormattable<T>;

#ifndef __cpp_lib_is_scoped_enum
    template <typename T, bool = std::is_enum_v<T>>
    struct is_scoped_enum : std::false_type
    {};

    template <typename T>
    struct is_scoped_enum<T, true> : std::bool_constant<!std::is_convertible_v<T, std::underlying_type_t<T>>>
    {};

    template <typename T>
    constexpr bool is_scoped_enum_v = is_scoped_enum<T>::value;
#endif

    template <typename T>
    concept
#if (!(defined(__clang__)) && defined(__GNUC__) && __GNUC__ < 10)
        bool
#endif
            ScopedEnum_t =
#ifdef __cpp_lib_is_scoped_enum
                std::is_scoped_enum_v<T>;
#else
            is_scoped_enum_v<T>;
#endif

}  // namespace llarp

#if !defined(USE_GHC_FILESYSTEM) && FMT_VERSION >= 80102

// Native support in fmt added after fmt 8.1.1
#include <fmt/std.h>

#else

#include <llarp/util/fs.hpp>

namespace fmt
{
    template <>
    struct formatter<fs::path> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const fs::path& p, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(p.string(), ctx);
        }
    };
}  // namespace fmt

#endif

namespace fmt
{
    template <llarp::ScopedEnum_t T>
    struct formatter<T, char> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(to_string(val), ctx);
        }
    };

}  // namespace fmt
