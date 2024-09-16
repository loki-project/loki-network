#include "intro.hpp"

#include <llarp/util/time.hpp>

namespace llarp::service
{
    static auto logcat = log::Cat("introduction");

    nlohmann::json Introduction::ExtractStatus() const
    {
        nlohmann::json obj{
            {"router", pivot_router.ToHex()},
            {"path", pivot_hop_id.ToHex()},
            {"expiresAt", to_json(expiry)},
            {"latency", to_json(latency)},
            {"version", uint64_t(version)}};
        return obj;
    }

    Introduction::Introduction(std::string buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{std::move(buf)};

            pivot_router.from_relay_address(btdc.require<std::string>("k"));
            latency = std::chrono::milliseconds{btdc.require<uint64_t>("l")};
            pivot_hop_id.from_string(btdc.require<std::string>("p"));
            expiry = std::chrono::milliseconds{btdc.require<uint64_t>("x")};
        }
        catch (...)
        {
            log::critical(logcat, "Error: Introduction failed to populate with bt encoded contents");
        }
    }

    void Introduction::bt_encode(oxenc::bt_list_producer& btlp) const
    {
        try
        {
            auto subdict = btlp.append_dict();
            bt_encode(subdict);
        }
        catch (...)
        {
            log::critical(logcat, "Error: Introduction failed to bt encode contents!");
        }
    }

    void Introduction::bt_encode(oxenc::bt_dict_producer& subdict) const
    {
        try
        {
            subdict.append("k", pivot_router.to_view());
            subdict.append("l", latency.count());
            subdict.append("p", pivot_hop_id.to_view());
            subdict.append("x", expiry.count());
        }
        catch (...)
        {
            log::critical(logcat, "Error: Introduction failed to bt encode contents!");
        }
    }

    bool Introduction::bt_decode(std::string_view buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};
            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "Introduction parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }

        return true;
    }

    void Introduction::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            pivot_router.from_string(btdc.require<std::string>("k"));
            latency = std::chrono::milliseconds{btdc.require<int64_t>("l")};
            pivot_hop_id.from_string(btdc.require<std::string>("p"));
            expiry = std::chrono::milliseconds{btdc.require<int64_t>("x")};
        }
        catch (...)
        {
            log::critical(logcat, "Introcuction failed to populate with bt encoded contents");
            throw;
        }
    }

    void Introduction::clear()
    {
        pivot_router.zero();
        pivot_hop_id.zero();
        latency = 0s;
        expiry = 0s;
    }

    std::string Introduction::to_string() const
    {
        return fmt::format(
            "[Intro k={} l={} p={} v={} x={}]",
            RouterID{pivot_router},
            latency.count(),
            pivot_hop_id,
            version,
            expiry.count());
    }

}  // namespace llarp::service
