#pragma once

#include "concept.hpp"

#include <oxen/log/format.hpp>

namespace llarp
{
    using namespace std::literals;
    using namespace oxen::log::literals;
}  // namespace llarp

#if !defined(USE_GHC_FILESYSTEM) && FMT_VERSION >= 80102

// Native support in fmt added after fmt 8.1.1
#include <fmt/std.h>

#else

#include <filesystem>

namespace fs = std::filesystem;

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
    template <llarp::concepts::is_scoped_enum T>
    struct formatter<T, char> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(to_string(val), ctx);
        }
    };

}  // namespace fmt
