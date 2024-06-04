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

    uint16_t checksum_ipv4(const void *header, uint8_t header_len);

    uint32_t tcpudp_checksum_ipv4(uint32_t src, uint32_t dest, uint32_t len, uint8_t proto, uint32_t sum);

    uint32_t tcp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);

    uint32_t udp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);

    namespace detail
    {
        inline static std::optional<std::string> parse_addr_string(std::string_view arg, std::string_view tld)
        {
            std::optional<std::string> ret = std::nullopt;

            if (auto pos = arg.find_first_of('.'); pos != std::string_view::npos)
            {
                auto _prefix = arg.substr(0, pos);
                // check the pubkey prefix is the right length
                if (_prefix.length() != PUBKEYSIZE)
                    return ret;

                // verify the tld is allowed
                auto _tld = arg.substr(pos);

                if (_tld == tld and TLD::allowed.count(_tld))
                    ret = _prefix;
            }

            return ret;
        };

        inline static std::pair<std::string, uint16_t> parse_addr(
            std::string_view addr, std::optional<uint16_t> default_port)
        {
            std::pair<std::string, uint16_t> result;

            if (auto p = addr.find_last_not_of("0123456789");
                p != std::string_view::npos && p + 2 <= addr.size() && addr[p] == ':')
            {
                if (!parse_int(addr.substr(p + 1), result.second))
                    throw std::invalid_argument{"Invalid address: could not parse port"};
                addr.remove_suffix(addr.size() - p);
            }
            else if (default_port)
            {
                result.second = *default_port;
            }
            else
            {
                throw std::invalid_argument{"Invalid address: no port was specified and there is no default"};
            }

            bool had_sq_brackets = false;

            if (!addr.empty() && addr.front() == '[' && addr.back() == ']')
            {
                addr.remove_prefix(1);
                addr.remove_suffix(1);
                had_sq_brackets = true;
            }

            if (auto p = addr.find_first_not_of("0123456789."); p != std::string_view::npos)
            {
                if (auto q = addr.find_first_not_of("0123456789abcdef:."); q != std::string_view::npos)
                    throw std::invalid_argument{"Invalid address: does not look like IPv4 or IPv6!"};
                else if (!had_sq_brackets)
                    throw std::invalid_argument{"Invalid address: IPv6 addresses require [...] square brackets"};
            }

            if (addr.empty())
                addr = "::";

            result.first = addr;
            return result;
        }

        inline constexpr size_t num_ipv4_private{272};

        inline constexpr std::array<ipv4_range, num_ipv4_private> generate_private_ipv4()
        {
            std::array<ipv4_range, num_ipv4_private> ret{};

            for (size_t n = 16; n < 32; ++n)
                ret[n - 16] = ipv4(172, n, 0, 0) / 16;

            for (size_t n = 0; n < 256; ++n)
                ret[n + 16] = ipv4(10, n, 0, 0) / 16;

            return ret;
        }

        // inline constexpr std::array<ipv6_range, num_ipv6_private> generate_private_ipv6()
        // {
        //     std::array<ipv6_range, num_ipv6_private> ret{};

        //     for (size_t n = 0; n < num_ipv6_private; ++n)
        //         ret[n] = ipv6(0xfd2e, 0x6c6f, 0x6b69, n) / 64;

        //     return ret;
        // }

    }  //  namespace detail

    /*
        16
        256

        528 total IPv4 addresses

        for (int oct = 16; oct <= 31; ++oct)
            if (auto range = IPRange::FromIPv4(172, oct, 0, 1, 16); good(range))
                return range;
        for (int oct = 0; oct <= 255; ++oct)
            if (auto range = IPRange::FromIPv4(10, oct, 0, 1, 16); good(range))
                return range;
    */
}  //  namespace llarp
