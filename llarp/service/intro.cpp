#include "intro.hpp"

#include <llarp/util/time.hpp>

namespace llarp::service
{
    StatusObject Introduction::ExtractStatus() const
    {
        StatusObject obj{
            {"router", router.ToHex()},
            {"path", path_id.ToHex()},
            {"expiresAt", to_json(expiry)},
            {"latency", to_json(latency)},
            {"version", uint64_t(version)}};
        return obj;
    }

    bool Introduction::decode_key(const llarp_buffer_t& key, llarp_buffer_t* buf)
    {
        bool read = false;
        if (!BEncodeMaybeReadDictEntry("k", router, read, key, buf))
            return false;
        if (!BEncodeMaybeReadDictInt("l", latency, read, key, buf))
            return false;
        if (!BEncodeMaybeReadDictEntry("p", path_id, read, key, buf))
            return false;
        if (!BEncodeMaybeReadDictInt("v", version, read, key, buf))
            return false;
        if (!BEncodeMaybeReadDictInt("x", expiry, read, key, buf))
            return false;
        return read;
    }

    Introduction::Introduction(std::string buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{std::move(buf)};

            router.from_snode_address(btdc.require<std::string>("k"));
            latency = std::chrono::milliseconds{btdc.require<uint64_t>("l")};
            path_id.from_string(btdc.require<std::string>("p"));
            expiry = std::chrono::milliseconds{btdc.require<uint64_t>("x")};
        }
        catch (...)
        {
            log::critical(intro_cat, "Error: Introduction failed to populate with bt encoded contents");
        }
    }

    void Introduction::bt_encode(oxenc::bt_list_producer& btlp) const
    {
        try
        {
            auto subdict = btlp.append_dict();

            subdict.append("k", router.ToView());
            subdict.append("l", latency.count());
            subdict.append("p", path_id.ToView());
            subdict.append("x", expiry.count());
        }
        catch (...)
        {
            log::critical(intro_cat, "Error: Introduction failed to bt encode contents!");
        }
    }

    void Introduction::bt_encode(oxenc::bt_dict_producer& subdict) const
    {
        try
        {
            subdict.append("k", router.ToView());
            subdict.append("l", latency.count());
            subdict.append("p", path_id.ToView());
            subdict.append("x", expiry.count());
        }
        catch (...)
        {
            log::critical(intro_cat, "Error: Introduction failed to bt encode contents!");
        }
    }

    void Introduction::Clear()
    {
        router.zero();
        path_id.zero();
        latency = 0s;
        expiry = 0s;
    }

    std::string Introduction::to_string() const
    {
        return fmt::format(
            "[Intro k={} l={} p={} v={} x={}]", RouterID{router}, latency.count(), path_id, version, expiry.count());
    }

}  // namespace llarp::service
