#pragma once

#include "meta.hpp"

#include <oxen/log/format.hpp>
#include <oxen/quic/format.hpp>

#include <optional>

namespace llarp
{
    using namespace std::literals;
    using namespace oxen::log::literals;

    namespace concepts
    {
        // Types can opt-in to being fmt-formattable by ensuring they have a ::to_string() method defined
        template <typename T>
        concept to_string_formattable = oxen::quic::concepts::ToStringFormattable<T>;
    }  // namespace concepts

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

// fmt added optional support in version 10.0.0
#if FMT_HAS_INCLUDE(<optional>) && FMT_VERSION <= 100000
namespace fmt
{
    template <typename T, typename Char>
    struct formatter<std::optional<T>, Char, std::enable_if_t<is_formattable<T, Char>::value>>
    {
      private:
        formatter<T, Char> underlying_;
        static constexpr basic_string_view<Char> optional =
            detail::string_literal<Char, 'o', 'p', 't', 'i', 'o', 'n', 'a', 'l', '('>{};
        static constexpr basic_string_view<Char> none = detail::string_literal<Char, 'n', 'o', 'n', 'e'>{};

        template <class U>
        FMT_CONSTEXPR static auto maybe_set_debug_format(U& u, bool set) -> decltype(u.set_debug_format(set))
        {
            u.set_debug_format(set);
        }

        template <class U>
        FMT_CONSTEXPR static void maybe_set_debug_format(U&, ...)
        {}

      public:
        template <typename ParseContext>
        FMT_CONSTEXPR auto parse(ParseContext& ctx)
        {
            maybe_set_debug_format(underlying_, true);
            return underlying_.parse(ctx);
        }

        template <typename FormatContext>
        auto format(const std::optional<T>& opt, FormatContext& ctx) const -> decltype(ctx.out())
        {
            if (!opt)
                return detail::write<Char>(ctx.out(), none);

            auto out = ctx.out();
            out = detail::write<Char>(out, optional);
            ctx.advance_to(out);
            out = underlying_.format(*opt, ctx);
            return detail::write(out, ')');
        }
    };
}  //  namespace fmt

#endif

namespace fmt
{
    template <llarp::concepts::scoped_enum T>
    struct formatter<T, char> : formatter<std::string_view>
    {
        template <typename FormatContext>
        auto format(const T& val, FormatContext& ctx) const
        {
            return formatter<std::string_view>::format(to_string(val), ctx);
        }
    };
}  // namespace fmt
