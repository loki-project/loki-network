#pragma once

#include "types.hpp"

#include <llarp/crypto/constants.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/str.hpp>

#include <charconv>
#include <optional>
#include <set>
#include <string_view>
#include <system_error>

namespace llarp
{
    namespace PREFIX
    {
        inline constexpr auto EXIT = "exit::"sv;
        inline constexpr auto LOKI = "loki::"sv;
        inline constexpr auto SNODE = "snode::"sv;
    }  //  namespace PREFIX

    namespace TLD
    {
        inline constexpr auto SNODE = ".snode"sv;
        inline constexpr auto LOKI = ".loki"sv;

        static std::set<std::string_view> allowed = {SNODE, LOKI};
    }  //  namespace TLD

    namespace detail
    {
        // inline auto utilcat = log::Cat("addrutils");
        std::optional<std::string> parse_addr_string(std::string_view arg, std::string_view tld);

        inline constexpr auto DIGITS = "0123456789"sv;
        inline constexpr auto PDIGITS = "0123456789."sv;
        inline constexpr auto ALDIGITS = "0123456789abcdef:."sv;

        std::pair<std::string, uint16_t> parse_addr(std::string_view addr, std::optional<uint16_t> default_port);

        inline constexpr size_t num_ipv4_private{272};

        inline constexpr std::array<ipv4_net, num_ipv4_private> generate_private_ipv4()
        {
            std::array<ipv4_net, num_ipv4_private> ret{};

            for (size_t n = 16; n < 32; ++n)
                ret[n - 16] = ipv4(172, n, 0, 1) % 16;

            for (size_t n = 0; n < 256; ++n)
                ret[n + 16] = ipv4(10, n, 0, 1) % 16;

            return ret;
        }
    }  //  namespace detail

}  //  namespace llarp
