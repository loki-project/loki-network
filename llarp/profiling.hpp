#pragma once

#include "path/path.hpp"
#include "router_id.hpp"
#include "util/bencode.hpp"
#include "util/thread/threading.hpp"

#include <map>

namespace oxenc
{
    class bt_dict_consumer;
    class bt_dict_producer;
}  // namespace oxenc

namespace llarp
{
    struct RouterProfile
    {
        static constexpr size_t MaxSize = 256;
        uint64_t conn_timeout = 0;
        uint64_t conn_success = 0;
        uint64_t path_success = 0;
        uint64_t path_fail = 0;
        uint64_t path_timeout = 0;
        llarp_time_t last_update = 0s;
        llarp_time_t last_decay = 0s;
        uint64_t version = llarp::constants::proto_version;

        RouterProfile() = default;
        RouterProfile(oxenc::bt_dict_consumer dict);

        void BEncode(oxenc::bt_dict_producer& dict) const;
        void BEncode(oxenc::bt_dict_producer&& dict) const
        {
            BEncode(dict);
        }

        void BDecode(oxenc::bt_dict_consumer dict);

        bool is_good(uint64_t chances) const;

        bool is_good_for_connect(uint64_t chances) const;

        bool is_good_for_path(uint64_t chances) const;

        /// decay stats
        void decay();

        // rotate stats if timeout reached
        void Tick();
    };

    struct Profiling
    {
        Profiling();

        inline static const int profiling_chances = 4;

        /// generic variant
        bool is_bad(const RouterID& r, uint64_t chances = profiling_chances);

        /// check if this router should have paths built over it
        bool is_bad_for_path(const RouterID& r, uint64_t chances = profiling_chances);

        /// check if this router should be connected directly to
        bool is_bad_for_connect(const RouterID& r, uint64_t chances = profiling_chances);

        void connect_timeout(const RouterID& r);

        void connect_succeess(const RouterID& r);

        void path_timeout(path::Path* p);

        void path_fail(path::Path* p);

        void path_success(path::Path* p);

        void hop_fail(const RouterID& r);

        void clear_profile(const RouterID& r);

        void Tick();

        bool load(const fs::path fname);

        bool save(const fs::path fname);

        bool should_save(llarp_time_t now) const;

        void disable();

        void enable();

       private:
        void BEncode(oxenc::bt_dict_producer& dict) const;

        void BDecode(oxenc::bt_dict_consumer dict);

        mutable util::Mutex _m;
        std::map<RouterID, RouterProfile> _profiles;
        llarp_time_t _last_save = 0s;
        std::atomic<bool> _profiling_disabled;
    };

}  // namespace llarp
