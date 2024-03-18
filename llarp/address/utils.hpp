#pragma once

#include "types.hpp"

#include <llarp/crypto/constants.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/types.hpp>

#include <charconv>
#include <optional>
#include <set>
#include <string_view>
#include <system_error>

namespace llarp
{
    namespace TLD
    {
        inline constexpr auto RELAY = ".snode"sv;
        inline constexpr auto CLIENT = ".loki"sv;

        std::set<std::string_view> allowed = {RELAY, CLIENT};
    }  //  namespace TLD

    uint16_t checksum_ipv4(const void *header, uint8_t header_len);

    uint32_t tcpudp_checksum_ipv4(uint32_t src, uint32_t dest, uint32_t len, uint8_t proto, uint32_t sum);

    uint32_t tcp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);

    uint32_t udp_checksum_ipv6(const struct in6_addr *saddr, const struct in6_addr *daddr, uint32_t len, uint32_t csum);

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

    template <typename T>
    static bool parse_int(const std::string_view str, T &value, int base = 10)
    {
        T tmp;
        auto *strend = str.data() + str.size();

        auto [p, ec] = std::from_chars(str.data(), strend, tmp, base);

        if (ec != std::errc() || p != strend)
            return false;

        value = tmp;
        return true;
    }

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
            if (!had_sq_brackets)
                throw std::invalid_argument{"Invalid address: IPv6 addresses require [...] square brackets"};
        }

        if (addr.empty())
            addr = "::";

        result.first = addr;
        return result;
    }
}  //  namespace llarp
