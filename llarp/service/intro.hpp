#pragma once

#include <llarp/crypto/types.hpp>
#include <llarp/path/path_types.hpp>

#include <oxenc/bt.h>

#include <iostream>
#include <set>

namespace llarp::service
{
    struct Introduction
    {
        RouterID pivot_router;
        HopID pivot_hop_id;
        std::chrono::milliseconds latency = 0s;
        std::chrono::milliseconds expiry = 0s;
        uint64_t version = llarp::constants::proto_version;

        Introduction() = default;
        Introduction(std::string buf);

        nlohmann::json ExtractStatus() const;

        bool is_expired(std::chrono::milliseconds now) const { return now >= expiry; }

        bool expires_soon(std::chrono::milliseconds now, std::chrono::milliseconds dlt = 30s) const
        {
            return is_expired(now + dlt);
        }

        std::string to_string() const;

        void bt_encode(oxenc::bt_list_producer& btlp) const;

        void bt_encode(oxenc::bt_dict_producer& subdict) const;

        bool bt_decode(std::string_view buf);

        void bt_decode(oxenc::bt_dict_consumer& btdc);

        void clear();

        bool operator<(const Introduction& other) const
        {
            return std::tie(expiry, pivot_hop_id, pivot_router, version, latency)
                < std::tie(other.expiry, other.pivot_hop_id, other.pivot_router, other.version, other.latency);
        }

        bool operator==(const Introduction& other) const
        {
            return std::tie(expiry, pivot_hop_id, pivot_router, version, latency)
                == std::tie(other.expiry, other.pivot_hop_id, other.pivot_router, other.version, other.latency);
        }

        bool operator!=(const Introduction& other) const { return !(*this == other); }
    };

    /// comparator for introduction timestamp in order of nearest to furthest expiry time
    struct IntroExpiryComparator
    {
        bool operator()(const Introduction& left, const Introduction& right) const
        {
            return left.expiry < right.expiry;
        }
    };

    using IntroductionSet = std::set<service::Introduction, service::IntroExpiryComparator>;

}  // namespace llarp::service

namespace std
{
    template <>
    struct hash<llarp::service::Introduction>
    {
        size_t operator()(const llarp::service::Introduction& i) const
        {
            return std::hash<llarp::PubKey>{}(i.pivot_router) ^ std::hash<llarp::HopID>{}(i.pivot_hop_id);
        }
    };
}  // namespace std
