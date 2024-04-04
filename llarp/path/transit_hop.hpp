#pragma once

#include <llarp/constants/path.hpp>
#include <llarp/path/path_types.hpp>
#include <llarp/router_id.hpp>
// #include <llarp/router/router.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/thread/queue.hpp>

namespace llarp
{
    struct Router;

    namespace path
    {
        struct TransitHopInfo
        {
            TransitHopInfo() = default;
            TransitHopInfo(RouterID down);

            HopID txID, rxID;
            RouterID upstream;
            RouterID downstream;

            std::string to_string() const;

            bool operator==(const TransitHopInfo& rhs) const
            {
                return std::tie(txID, rxID, upstream, downstream)
                    == std::tie(rhs.txID, rhs.rxID, rhs.upstream, rhs.downstream);
            }

            bool operator!=(const TransitHopInfo& rhs) const
            {
                return not(*this == rhs);
            }

            bool operator<(const TransitHopInfo& rhs) const
            {
                return std::tie(txID, rxID, upstream, downstream)
                    < std::tie(rhs.txID, rhs.rxID, rhs.upstream, rhs.downstream);
            }
        };

        struct TransitHop : std::enable_shared_from_this<TransitHop>
        {
            TransitHop() = default;

            // This static factory function is used in path-build logic. The exceptions thrown are the exact response
            // bodies passed to message::respond(...) function
            static std::shared_ptr<TransitHop> deserialize_hop(
                oxenc::bt_dict_consumer& btdc, const RouterID& src, Router& r, ustring symmkey, ustring symmnonce);

            TransitHopInfo info;
            SharedSecret shared;
            SymmNonce nonceXOR;
            std::chrono::milliseconds started = 0s;
            // 10 minutes default
            std::chrono::milliseconds lifetime = DEFAULT_LIFETIME;
            uint8_t version;
            std::chrono::milliseconds last_activity = 0s;
            bool terminal_hop{false};

            HopID RXID() const
            {
                return info.rxID;
            }

            void Stop();

            bool destroy = false;

            bool operator<(const TransitHop& other) const
            {
                return info < other.info;
            }

            bool IsEndpoint(const RouterID& us) const
            {
                return info.upstream == us;
            }

            std::chrono::milliseconds ExpireTime() const;

            std::chrono::milliseconds LastRemoteActivityAt() const
            {
                return last_activity;
            }

            std::string to_string() const;

            bool is_expired(std::chrono::milliseconds now) const;

            bool ExpiresSoon(std::chrono::milliseconds now, std::chrono::milliseconds dlt) const
            {
                return now >= ExpireTime() - dlt;
            }

            void QueueDestroySelf(Router* r);

          private:
            void SetSelfDestruct();
        };
    }  // namespace path
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::path::TransitHopInfo>
    {
        std::size_t operator()(const llarp::path::TransitHopInfo& a) const
        {
            hash<llarp::RouterID> RHash{};
            hash<llarp::HopID> PHash{};
            return RHash(a.upstream) ^ RHash(a.downstream) ^ PHash(a.txID) ^ PHash(a.rxID);
        }
    };
}  // namespace std
