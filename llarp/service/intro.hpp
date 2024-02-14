#pragma once

#include <llarp/crypto/types.hpp>
#include <llarp/path/path_types.hpp>
#include <llarp/util/bencode.hpp>
#include <llarp/util/types.hpp>

#include <oxenc/bt.h>

#include <iostream>

namespace
{
    static auto intro_cat = llarp::log::Cat("lokinet.intro");
}  // namespace

namespace llarp::service
{
    struct Introduction
    {
        RouterID router;
        HopID path_id;
        llarp_time_t latency = 0s;
        llarp_time_t expiry = 0s;
        uint64_t version = llarp::constants::proto_version;

        Introduction() = default;
        Introduction(std::string buf);

        StatusObject ExtractStatus() const;

        bool IsExpired(llarp_time_t now) const
        {
            return now >= expiry;
        }

        bool ExpiresSoon(llarp_time_t now, llarp_time_t dlt = 30s) const
        {
            return IsExpired(now + dlt);
        }

        std::string to_string() const;

        void bt_encode(oxenc::bt_list_producer& btlp) const;
        void bt_encode(oxenc::bt_dict_producer& subdict) const;

        bool BDecode(llarp_buffer_t* buf)
        {
            return bencode_decode_dict(*this, buf);
        }

        bool decode_key(const llarp_buffer_t& key, llarp_buffer_t* buf);

        void Clear();

        bool operator<(const Introduction& other) const
        {
            return std::tie(expiry, path_id, router, version, latency)
                < std::tie(other.expiry, other.path_id, other.router, other.version, other.latency);
        }

        bool operator==(const Introduction& other) const
        {
            return path_id == other.path_id && router == other.router;
        }

        bool operator!=(const Introduction& other) const
        {
            return path_id != other.path_id || router != other.router;
        }
    };

    /// comparator for introset timestamp
    struct CompareIntroTimestamp
    {
        bool operator()(const Introduction& left, const Introduction& right) const
        {
            return left.expiry > right.expiry;
        }
    };
}  // namespace llarp::service

template <>
inline constexpr bool llarp::IsToStringFormattable<llarp::service::Introduction> = true;

namespace std
{
    template <>
    struct hash<llarp::service::Introduction>
    {
        size_t operator()(const llarp::service::Introduction& i) const
        {
            return std::hash<llarp::PubKey>{}(i.router) ^ std::hash<llarp::HopID>{}(i.path_id);
        }
    };
}  // namespace std
