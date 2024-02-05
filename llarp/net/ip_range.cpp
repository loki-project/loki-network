#include "ip_range.hpp"

#include <llarp/util/bencode.h>

#include <oxenc/bt_serialize.h>

namespace llarp
{
    void IPRange::bt_encode(oxenc::bt_list_producer& btlp) const
    {
        try
        {
            btlp.append(to_string());
        }
        catch (...)
        {
            log::critical(net_cat, "Error: IPRange failed to bt encode contents");
        }
    }

    bool IPRange::BDecode(llarp_buffer_t* buf)
    {
        const auto* start = buf->cur;
        if (not bencode_discard(buf))
            return false;
        std::string_view data{reinterpret_cast<const char*>(start), static_cast<size_t>(buf->cur - start)};
        std::string str;
        try
        {
            oxenc::bt_deserialize(data, str);
        }
        catch (std::exception&)
        {
            return false;
        }
        return FromString(str);
    }

    bool IPRange::FromString(std::string str)
    {
        const auto colinpos = str.find(":");
        const auto slashpos = str.find("/");
        std::string bitsstr;
        if (slashpos != std::string::npos)
        {
            bitsstr = str.substr(slashpos + 1);
            str = str.substr(0, slashpos);
        }
        if (colinpos == std::string::npos)
        {
            huint32_t ip;
            if (!ip.FromString(str))
                return false;
            addr = net::ExpandV4(ip);
            if (!bitsstr.empty())
            {
                const auto bits = stoi(bitsstr);
                if (bits < 0 || bits > 32)
                    return false;
                netmask_bits = netmask_ipv6_bits(96 + bits);
            }
            else
                netmask_bits = netmask_ipv6_bits(128);
        }
        else
        {
            if (!addr.FromString(str))
                return false;
            if (!bitsstr.empty())
            {
                auto bits = atoi(bitsstr.c_str());
                if (bits < 0 || bits > 128)
                    return false;
                netmask_bits = netmask_ipv6_bits(bits);
            }
            else
            {
                netmask_bits = netmask_ipv6_bits(128);
            }
        }
        return true;
    }

    std::string IPRange::BaseAddressString() const
    {
        if (IsV4())
        {
            const huint32_t addr4 = net::TruncateV6(addr);
            return addr4.to_string();
        }
        return addr.to_string();
    }

    std::string IPRange::NetmaskString() const
    {
        if (IsV4())
        {
            const huint32_t mask = net::TruncateV6(netmask_bits);
            return mask.to_string();
        }
        return netmask_bits.to_string();
    }

    std::optional<IPRange> IPRange::FindPrivateRange(const std::list<IPRange>& excluding)
    {
        auto good = [&excluding](const IPRange& range) -> bool {
            for (const auto& ex : excluding)
                if (ex * range)
                    return false;
            return true;
        };
        for (int oct = 16; oct <= 31; ++oct)
            if (auto range = IPRange::FromIPv4(172, oct, 0, 1, 16); good(range))
                return range;
        for (int oct = 0; oct <= 255; ++oct)
            if (auto range = IPRange::FromIPv4(10, oct, 0, 1, 16); good(range))
                return range;
        for (int oct = 0; oct <= 255; ++oct)
            if (auto range = IPRange::FromIPv4(192, 168, oct, 1, 24); good(range))
                return range;
        return std::nullopt;
    }

}  // namespace llarp
