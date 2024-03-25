#include "profiling.hpp"

#include "util/file.hpp"

#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>

using oxenc::bt_dict_consumer;
using oxenc::bt_dict_producer;

namespace llarp
{
    static auto logcat = log::Cat("profiling");

    RouterProfile::RouterProfile(bt_dict_consumer& btdc)
    {
        try
        {
            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "RouterProfile parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }
    }

    void RouterProfile::bt_encode(bt_dict_producer& btdp) const
    {
        btdp.append("g", conn_success);
        btdp.append("p", path_success);
        btdp.append("q", path_timeout);
        btdp.append("s", path_fail);
        btdp.append("t", conn_timeout);
        btdp.append("u", last_update.count());
        btdp.append("v", version);
    }

    void RouterProfile::bt_decode(bt_dict_consumer& btdc)
    {
        try
        {
            conn_success = btdc.require<uint64_t>("g");
            path_success = btdc.require<uint64_t>("p");
            path_timeout = btdc.require<uint64_t>("q");
            path_fail = btdc.require<uint64_t>("s");
            conn_timeout = btdc.require<uint64_t>("t");
            last_update = std::chrono::milliseconds{btdc.require<uint64_t>("u")};
            version = btdc.require<uint64_t>("v");
        }
        catch (...)
        {
            log::critical(logcat, "RouterProfile failed to decode contents");
            throw;
        }
    }

    bool RouterProfile::bt_decode(std::string_view buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};
            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "RouterProfile parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }

        return true;
    }

    void RouterProfile::decay()
    {
        conn_success /= 2;
        conn_timeout /= 2;
        path_success /= 2;
        path_fail /= 2;
        path_timeout /= 2;
        last_decay = llarp::time_now_ms();
    }

    void RouterProfile::Tick()
    {
        static constexpr auto updateInterval = 30s;
        const auto now = llarp::time_now_ms();
        if (last_decay < now && now - last_decay > updateInterval)
            decay();
    }

    bool RouterProfile::is_good(uint64_t chances) const
    {
        if (conn_timeout > chances)
            return conn_timeout < conn_success && (path_success * chances) > path_fail;
        return (path_success * chances) > path_fail;
    }

    static constexpr bool checkIsGood(uint64_t fails, uint64_t success, uint64_t chances)
    {
        if (fails > 0 && (fails + success) >= chances)
            return (success / fails) > 1;
        if (success == 0)
            return fails < chances;
        return true;
    }

    bool RouterProfile::is_good_for_connect(uint64_t chances) const
    {
        return checkIsGood(conn_timeout, conn_success, chances);
    }

    bool RouterProfile::is_good_for_path(uint64_t chances) const
    {
        if (path_timeout > chances)
            return false;
        return checkIsGood(path_fail, path_success, chances);
    }

    Profiling::Profiling() : _profiling_disabled(false)
    {}

    void Profiling::disable()
    {
        _profiling_disabled.store(true);
    }

    void Profiling::enable()
    {
        _profiling_disabled.store(false);
    }

    bool Profiling::is_bad_for_connect(const RouterID& r, uint64_t chances)
    {
        if (_profiling_disabled.load())
            return false;
        util::Lock lock{_m};
        auto itr = _profiles.find(r);
        if (itr == _profiles.end())
            return false;
        return not itr->second.is_good_for_connect(chances);
    }

    bool Profiling::is_bad_for_path(const RouterID& r, uint64_t chances)
    {
        if (_profiling_disabled.load())
            return false;
        util::Lock lock{_m};
        auto itr = _profiles.find(r);
        if (itr == _profiles.end())
            return false;
        return not itr->second.is_good_for_path(chances);
    }

    bool Profiling::is_bad(const RouterID& r, uint64_t chances)
    {
        if (_profiling_disabled.load())
            return false;
        util::Lock lock{_m};
        auto itr = _profiles.find(r);
        if (itr == _profiles.end())
            return false;
        return not itr->second.is_good(chances);
    }

    void Profiling::Tick()
    {
        util::Lock lock(_m);
        for (auto& [rid, profile] : _profiles)
            profile.Tick();
    }

    void Profiling::connect_timeout(const RouterID& r)
    {
        util::Lock lock{_m};
        auto& profile = _profiles[r];
        profile.conn_timeout += 1;
        profile.last_update = llarp::time_now_ms();
    }

    void Profiling::connect_succeess(const RouterID& r)
    {
        util::Lock lock{_m};
        auto& profile = _profiles[r];
        profile.conn_success += 1;
        profile.last_update = llarp::time_now_ms();
    }

    void Profiling::clear_profile(const RouterID& r)
    {
        util::Lock lock{_m};
        _profiles.erase(r);
    }

    void Profiling::hop_fail(const RouterID& r)
    {
        util::Lock lock{_m};
        auto& profile = _profiles[r];
        profile.path_fail += 1;
        profile.last_update = llarp::time_now_ms();
    }

    void Profiling::path_fail(path::Path* p)
    {
        util::Lock lock{_m};
        bool first = true;
        for (const auto& hop : p->hops)
        {
            // don't mark first hop as failure because we are connected to it directly
            if (first)
                first = false;
            else
            {
                auto& profile = _profiles[hop.rc.router_id()];
                profile.path_fail += 1;
                profile.last_update = llarp::time_now_ms();
            }
        }
    }

    void Profiling::path_timeout(path::Path* p)
    {
        util::Lock lock{_m};
        for (const auto& hop : p->hops)
        {
            auto& profile = _profiles[hop.rc.router_id()];
            profile.path_timeout += 1;
            profile.last_update = llarp::time_now_ms();
        }
    }

    void Profiling::path_success(path::Path* p)
    {
        util::Lock lock{_m};
        const auto sz = p->hops.size();
        for (const auto& hop : p->hops)
        {
            auto& profile = _profiles[hop.rc.router_id()];
            // redeem previous fails by halfing the fail count and setting timeout to zero
            profile.path_fail /= 2;
            profile.path_timeout = 0;
            // mark success at hop
            profile.path_success += sz;
            profile.last_update = llarp::time_now_ms();
        }
    }

    bool Profiling::save(const fs::path fpath)
    {
        std::string buf;
        {
            util::Lock lock{_m};
            buf.resize((_profiles.size() * (RouterProfile::MaxSize + 32 + 8)) + 8);
            bt_dict_producer d{buf.data(), buf.size()};
            try
            {
                BEncode(d);
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Failed to encode profiling data: {}", e.what());
                return false;
            }
            buf.resize(d.end() - buf.data());
        }

        try
        {
            util::buffer_to_file(fpath, buf);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Failed to save profiling data to {}: {}", fpath, e.what());
            return false;
        }

        _last_save = llarp::time_now_ms();
        return true;
    }

    void Profiling::BEncode(bt_dict_producer& dict) const
    {
        for (const auto& [r_id, profile] : _profiles)
        {
            auto subdict = dict.append_dict(r_id.ToView());
            profile.bt_encode(subdict);
        }
    }

    void Profiling::BDecode(bt_dict_consumer dict)
    {
        _profiles.clear();
        while (dict)
        {
            auto [rid, subdict] = dict.next_dict_consumer();
            if (rid.size() != RouterID::SIZE)
                throw std::invalid_argument{"invalid RouterID"};
            _profiles.emplace(reinterpret_cast<const uint8_t*>(rid.data()), subdict);
        }
    }

    bool Profiling::load(const fs::path fname)
    {
        try
        {
            std::string data = util::file_to_string(fname);
            util::Lock lock{_m};
            BDecode(bt_dict_consumer{data});
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "failed to load router profiles from {}: {}", fname, e.what());
            return false;
        }
        _last_save = llarp::time_now_ms();
        return true;
    }

    bool Profiling::should_save(std::chrono::milliseconds now) const
    {
        auto dlt = now - _last_save;
        return dlt > 1min;
    }
}  // namespace llarp
