#pragma once

#include <llarp/constants/path.hpp>
#include <llarp/path/path_types.hpp>
#include <llarp/router_id.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/thread/queue.hpp>

namespace llarp
{
    struct Router;

    namespace path
    {
        struct TransitHop : std::enable_shared_from_this<TransitHop>
        {
          private:
            HopID _txid, _rxid;
            RouterID _upstream;
            RouterID _downstream;

          public:
            TransitHop() = default;

            TransitHop(Router& r, const RouterID& src, ustring symmkey, ustring symmnonce);

            // This static factory function is used in path-build logic. The exceptions thrown are the exact response
            // bodies passed to message::respond(...) function
            static std::shared_ptr<TransitHop> deserialize_hop(
                oxenc::bt_dict_consumer& btdc, const RouterID& src, Router& r, ustring symmkey, ustring symmnonce);

            SharedSecret shared;
            SymmNonce nonceXOR;
            std::chrono::milliseconds started = 0s;
            // 10 minutes default
            std::chrono::milliseconds lifetime = DEFAULT_LIFETIME;
            uint8_t version;
            std::chrono::milliseconds _last_activity = 0s;
            bool terminal_hop{false};

            RouterID& upstream()
            {
                return _upstream;
            }

            const RouterID& upstream() const
            {
                return _upstream;
            }

            RouterID& downstream()
            {
                return _downstream;
            }

            const RouterID& downstream() const
            {
                return _downstream;
            }

            HopID rxid()
            {
                return _rxid;
            }

            const HopID& rxid() const
            {
                return _rxid;
            }

            HopID txid()
            {
                return _txid;
            }

            const HopID& txid() const
            {
                return _txid;
            }

            void Stop();

            bool destroy = false;

            bool operator<(const TransitHop& other) const
            {
                return std::tie(_txid, _rxid, _upstream, _downstream)
                    < std::tie(other._txid, other._rxid, other._upstream, other._downstream);
            }

            bool operator==(const TransitHop& other) const
            {
                return std::tie(_txid, _rxid, _upstream, _downstream)
                    == std::tie(other._txid, other._rxid, other._upstream, other._downstream);
            }

            bool operator!=(const TransitHop& other) const
            {
                return !(*this == other);
            }

            std::chrono::milliseconds expiry_time() const;

            std::chrono::milliseconds last_activity() const
            {
                return _last_activity;
            }

            std::string to_string() const;

            bool is_expired(std::chrono::milliseconds now) const;

            bool ExpiresSoon(std::chrono::milliseconds now, std::chrono::milliseconds dlt) const
            {
                return now >= expiry_time() - dlt;
            }

            void QueueDestroySelf(Router* r);

          private:
            void SetSelfDestruct();
        };
    }  // namespace path
}  // namespace llarp

namespace std
{
    // template <>
    // struct hash<llarp::path::TransitHopInfo>
    // {
    //     std::size_t operator()(const llarp::path::TransitHopInfo& a) const
    //     {
    //         hash<llarp::RouterID> RHash{};
    //         hash<llarp::HopID> PHash{};
    //         return RHash(a.upstream) ^ RHash(a.downstream) ^ PHash(a.txID) ^ PHash(a.rxID);
    //     }
    // };
}  // namespace std
