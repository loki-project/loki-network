#include "srv_data.hpp"

// #include <llarp/util/bencode.h>
#include <llarp/util/str.hpp>
#include <llarp/util/types.hpp>

#include <oxenc/bt_serialize.h>

namespace llarp::dns
{
    static auto logcat = log::Cat("SRVData");

    SRVData::SRVData(std::string _proto, uint16_t _priority, uint16_t _weight, uint16_t _port, std::string _target)
        : service_proto{std::move(_proto)},
          priority{_priority},
          weight{_weight},
          port{_port},
          target{std::move(_target)}
    {
        if (not is_valid())
            throw std::invalid_argument{"Invalid SRVData!"};
    }

    SRVData::SRVData(std::string bt)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{bt};
            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "SRVData parsing exception: {}", e.what());
        }
    }

    bool SRVData::is_valid() const
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

    bool SRVData::from_string(std::string_view srvString)
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

        return is_valid();
    }

    std::string SRVData::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        btdp.append("p", port);
        btdp.append("s", service_proto);
        btdp.append("t", target);
        btdp.append("u", priority);
        btdp.append("w", weight);

        return std::move(btdp).str();
    }

    bool SRVData::bt_decode(std::string buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};
            return bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "SRVData parsing exception: {}", e.what());
            return false;
        }
    }

    bool SRVData::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            port = btdc.require<uint16_t>("p");
            service_proto = btdc.require<std::string>("s");
            target = btdc.require<std::string>("t");
            priority = btdc.require<uint16_t>("u");
            weight = btdc.require<uint16_t>("w");

            return is_valid();
        }
        catch (const std::exception& e)
        {
            auto err = "SRVData parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }
    }

    std::optional<SRVData> SRVData::from_srv_string(std::string buf)
    {
        if (SRVData ret; ret.from_string(std::move(buf)))
            return ret;

        return std::nullopt;
    }

    StatusObject SRVData::ExtractStatus() const
    {
        return StatusObject{
            {"proto", service_proto}, {"priority", priority}, {"weight", weight}, {"port", port}, {"target", target}};
    }
}  // namespace llarp::dns
