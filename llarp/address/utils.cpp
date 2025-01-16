#include "utils.hpp"

namespace llarp
{
    static auto logcat = log::Cat("address-utils");

    namespace detail
    {
        std::optional<std::string> parse_addr_string(std::string_view arg, std::string_view tld)
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

        std::pair<std::string, uint16_t> parse_addr(std::string_view addr, std::optional<uint16_t> default_port)
        {
            std::pair<std::string, uint16_t> result;
            auto &[host, port] = result;

            if (auto p = addr.find_last_not_of(DIGITS);
                p != std::string_view::npos && p + 2 <= addr.size() && addr[p] == ':')
            {
                if (!parse_int(addr.substr(p + 1), port))
                    throw std::invalid_argument{"Invalid address: could not parse port"};
                addr.remove_suffix(addr.size() - p);
            }
            else if (default_port.has_value())  // use ::has_value() in case default_port is set but is == 0
            {
                port = *default_port;
            }
            else
                throw std::invalid_argument{
                    "Invalid address: argument contains no port and no default was specified (input:{})"_format(addr)};

            bool had_sq_brackets = false;

            if (!addr.empty() && addr.front() == '[' && addr.back() == ']')
            {
                addr.remove_prefix(1);
                addr.remove_suffix(1);
                had_sq_brackets = true;
            }

            if (auto p = addr.find_first_not_of(PDIGITS); p != std::string_view::npos)
            {
                if (auto q = addr.find_first_not_of(ALDIGITS); q != std::string_view::npos)
                    throw std::invalid_argument{"Invalid address: does not look like IPv4 or IPv6!"};
                if (!had_sq_brackets)
                    throw std::invalid_argument{"Invalid address: IPv6 addresses require [...] square brackets"};
            }

            host = addr;
            return result;
        }
    }  // namespace detail
}  // namespace llarp
