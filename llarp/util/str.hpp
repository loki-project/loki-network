#pragma once

#include <fmt/format.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <iterator>
#include <string_view>
#include <vector>

namespace llarp
{
    /// Returns true if the first argument begins with the second argument
    inline constexpr bool starts_with(std::string_view str, std::string_view prefix)
    {
        return str.substr(0, prefix.size()) == prefix;
    }

    /// Returns true if the first argument ends with the second argument
    inline constexpr bool ends_with(std::string_view str, std::string_view suffix)
    {
        return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
    }

    /// removes a prefix from a string if it exists
    inline constexpr std::string_view strip_prefix(std::string_view str, std::string_view prefix)
    {
        if (starts_with(str, prefix))
            return str.substr(prefix.size());
        return str;
    }

    /// Splits a string on some delimiter string and returns a vector of string_view's pointing into
    /// the pieces of the original string.  The pieces are valid only as long as the original string
    /// remains valid.  Leading and trailing empty substrings are not removed.  If delim is empty
    /// you get back a vector of string_views each viewing one character.  If `trim` is true then
    /// leading and trailing empty values will be suppressed.
    ///
    ///     auto v = split("ab--c----de", "--"); // v is {"ab", "c", "", "de"}
    ///     auto v = split("abc", ""); // v is {"a", "b", "c"}
    ///     auto v = split("abc", "c"); // v is {"ab", ""}
    ///     auto v = split("abc", "c", true); // v is {"ab"}
    ///     auto v = split("-a--b--", "-"); // v is {"", "a", "", "b", "", ""}
    ///     auto v = split("-a--b--", "-", true); // v is {"a", "", "b"}
    ///
    std::vector<std::string_view> split(std::string_view str, std::string_view delim, bool trim = false);

    /// Splits a string on any 1 or more of the given delimiter characters and returns a vector of
    /// string_view's pointing into the pieces of the original string.  If delims is empty this
    /// works the same as split().  `trim` works like split (suppresses leading and trailing empty
    /// string pieces).
    ///
    ///     auto v = split_any("abcdedf", "dcx"); // v is {"ab", "e", "f"}
    std::vector<std::string_view> split_any(std::string_view str, std::string_view delims, bool trim = false);

    /// Joins [begin, end) with a delimiter and returns the resulting string.  Elements can be
    /// anything that is fmt formattable.
    template <typename It>
    std::string join(std::string_view delimiter, It begin, It end)
    {
        return fmt::format("{}", fmt::join(delimiter, begin, end));
    }

    /// Wrapper around the above that takes a container and passes c.begin(), c.end() to the above.
    template <typename Container>
    std::string join(std::string_view delimiter, const Container& c)
    {
        return join(delimiter, c.begin(), c.end());
    }

    /// Parses an integer of some sort from a string, requiring that the entire string be consumed
    /// during parsing.  Return false if parsing failed, sets `value` and returns true if the entire
    /// string was consumed.
    template <typename T>
    bool parse_int(const std::string_view str, T& value, int base = 10)
    {
        T tmp;
        auto* strend = str.data() + str.size();
        auto [p, ec] = std::from_chars(str.data(), strend, tmp, base);
        if (ec != std::errc() || p != strend)
            return false;
        value = tmp;
        return true;
    }

    std::string lowercase_ascii_string(std::string src);

    std::string_view TrimWhitespace(std::string_view str);

    /// convert a "normal" string into a wide string
    std::wstring to_wide(std::string data);

}  // namespace llarp
