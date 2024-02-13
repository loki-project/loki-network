#include "name.hpp"

#include <llarp/net/net_bits.hpp>
#include <llarp/util/str.hpp>

#include <oxenc/hex.h>

namespace llarp::dns
{
    std::optional<std::string> DecodeName(llarp_buffer_t* buf, bool trimTrailingDot)
    {
        if (buf->size_left() < 1)
            return std::nullopt;
        auto result = std::make_optional<std::string>();
        auto& name = *result;
        size_t l;
        do
        {
            l = *buf->cur;
            buf->cur++;
            if (l)
            {
                if (buf->size_left() < l)
                    return std::nullopt;

                name.append((const char*)buf->cur, l);
                name += '.';
            }
            buf->cur = buf->cur + l;
        } while (l);
        /// trim off last dot
        if (trimTrailingDot)
            name.pop_back();
        return result;
    }

    bool EncodeNameTo(llarp_buffer_t* buf, std::string_view name)
    {
        if (name.size() && name.back() == '.')
            name.remove_suffix(1);

        for (auto part : llarp::split(name, "."))
        {
            size_t l = part.length();
            if (l > 63)
                return false;
            *(buf->cur) = l;
            buf->cur++;
            if (buf->size_left() < l)
                return false;
            if (l)
            {
                std::memcpy(buf->cur, part.data(), l);
                buf->cur += l;
            }
            else
                break;
        }
        *buf->cur = 0;
        buf->cur++;
        return true;
    }

    std::optional<ip> DecodePTR(std::string_view name)
    {
        bool isV6 = false;
        auto pos = name.find(".in-addr.arpa");

        if (pos == std::string::npos)
        {
            pos = name.find(".ip6.arpa");
            isV6 = true;
        }

        if (pos == std::string::npos)
            return std::nullopt;

        name = name.substr(0, pos + 1);
        const auto numdots = std::count(name.begin(), name.end(), '.');

        if (numdots == 4 && !isV6)
        {
            std::array<uint8_t, 4> q;

            for (int i = 3; i >= 0; i--)
            {
                pos = name.find('.');
                if (!llarp::parse_int(name.substr(0, pos), q[i]))
                    return std::nullopt;
                name.remove_prefix(pos + 1);
            }

            return ipv4(q[0], q[1], q[2], q[3]);
        }
        if (numdots == 32 && name.size() == 64 && isV6)
        {
            // We're going to convert from nybbles a.b.c.d.e.f.0.1.2.3.[...] into hex string
            // "badcfe1032...", then decode the hex string to bytes.
            std::array<char, 32> in;
            auto in_pos = in.data();

            for (size_t i = 0; i < 64; i += 4)
            {
                if (not(oxenc::is_hex_digit(name[i]) and name[i + 1] == '.' and oxenc::is_hex_digit(name[i + 2])
                        and name[i + 3] == '.'))
                    return std::nullopt;

                // Flip the nybbles because the smallest one is first
                *in_pos++ = name[i + 2];
                *in_pos++ = name[i];
            }

            assert(in_pos == in.data() + in.size());

            // our string right now is the little endian representation, so load it as such on
            // little endian, or in reverse on big endian.
            if constexpr (oxenc::little_endian)
            {
                auto hex = oxenc::from_hex(in.begin(), in.end());
                return ipv6{reinterpret_cast<const unsigned char*>(hex.data())};
            }
            else
                return ipv6{reinterpret_cast<const unsigned char*>(in.data())};
        }
        return std::nullopt;
    }

    bool NameIsReserved(std::string_view name)
    {
        const std::vector<std::string_view> reserved_names = {
            ".snode.loki"sv, ".loki.loki"sv, ".snode.loki."sv, ".loki.loki."sv};
        for (const auto& reserved : reserved_names)
        {
            if (ends_with(name, reserved))  // subdomain foo.loki.loki
                return true;
            if (name == reserved.substr(1))  // loki.loki itself
                return true;
        }
        return false;
    }
}  // namespace llarp::dns
