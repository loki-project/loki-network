#include "srv_data.hpp"

#include <llarp/util/bencode.h>
#include <llarp/util/str.hpp>
#include <llarp/util/types.hpp>

#include <oxenc/bt_serialize.h>

namespace llarp::dns
{
    static auto logcat = log::Cat("dns");

    bool SRVData::IsValid() const
    {
        // if target is of first two forms outlined above
        if (target == "." or target.size() == 0)
        {
            return true;
        }

        // check target size is not absurd
        if (target.size() > TARGET_MAX_SIZE)
        {
            log::warning(logcat, "SRVData target larger than max size ({})", TARGET_MAX_SIZE);
            return false;
        }

        // does target end in .loki?
        size_t pos = target.find(".loki");
        if (pos != std::string::npos && pos == (target.size() - 5))
        {
            return true;
        }

        // does target end in .snode?
        pos = target.find(".snode");
        if (pos != std::string::npos && pos == (target.size() - 6))
        {
            return true;
        }

        // if we're here, target is invalid
        log::warning(logcat, "SRVData invalid");
        return false;
    }

    SRVTuple SRVData::toTuple() const
    {
        return std::make_tuple(service_proto, priority, weight, port, target);
    }

    SRVData SRVData::fromTuple(SRVTuple tuple)
    {
        SRVData s;

        std::tie(s.service_proto, s.priority, s.weight, s.port, s.target) = std::move(tuple);

        return s;
    }

    bool SRVData::fromString(std::string_view srvString)
    {
        log::debug(logcat, "SRVData::fromString(\"{}\")", srvString);

        // split on spaces, discard trailing empty strings
        auto splits = split(srvString, " ", false);

        if (splits.size() != 5 && splits.size() != 4)
        {
            log::warning(logcat, "SRV record should have either 4 or 5 space-separated parts");
            return false;
        }

        service_proto = splits[0];

        if (not parse_int(splits[1], priority))
        {
            log::warning(logcat, "SRV record failed to parse \"{}\" as uint16_t (priority)", splits[1]);
            return false;
        }

        if (not parse_int(splits[2], weight))
        {
            log::warning(logcat, "SRV record failed to parse \"{}\" as uint16_t (weight)", splits[2]);
            return false;
        }

        if (not parse_int(splits[3], port))
        {
            log::warning(logcat, "SRV record failed to parse \"{}\" as uint16_t (port)", splits[3]);
            return false;
        }

        if (splits.size() == 5)
            target = splits[4];
        else
            target = "";

        return IsValid();
    }

    std::string SRVData::bt_encode() const
    {
        return oxenc::bt_serialize(toTuple());
    }

    bool SRVData::BDecode(llarp_buffer_t* buf)
    {
        uint8_t* begin = buf->cur;
        if (not bencode_discard(buf))
            return false;
        uint8_t* end = buf->cur;
        std::string_view srvString{reinterpret_cast<char*>(begin), static_cast<std::size_t>(end - begin)};
        try
        {
            SRVTuple tuple{};
            oxenc::bt_deserialize(srvString, tuple);
            *this = fromTuple(std::move(tuple));
            return IsValid();
        }
        catch (const oxenc::bt_deserialize_invalid&)
        {
            return false;
        };
    }

    StatusObject SRVData::ExtractStatus() const
    {
        return StatusObject{
            {"proto", service_proto}, {"priority", priority}, {"weight", weight}, {"port", port}, {"target", target}};
    }
}  // namespace llarp::dns
