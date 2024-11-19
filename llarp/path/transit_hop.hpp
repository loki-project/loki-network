#pragma once

#include "path_types.hpp"

#include <llarp/constants/path.hpp>
#include <llarp/contact/router_id.hpp>
#include <llarp/util/compare_ptr.hpp>

namespace llarp
{
    struct Router;

    namespace path
    {
        struct TransitHop : std::enable_shared_from_this<TransitHop>
        {
            HopID _txid, _rxid;

            RouterID _upstream;
            RouterID _rid;
            RouterID _downstream;

            TransitHop() = default;

            void deserialize(oxenc::bt_dict_consumer&& btdc, const RouterID& src, const Router& r);

            shared_kx_data kx{};

            std::chrono::milliseconds expiry{0s};

            uint8_t version;
            std::chrono::milliseconds _last_activity{0s};
            bool terminal_hop{false};

            void bt_decode(oxenc::bt_dict_consumer&& btdc);

            std::string bt_encode() const;

            RouterID router_id() { return _rid; }
            const RouterID& router_id() const { return _rid; }

            RouterID upstream() { return _upstream; }
            const RouterID& upstream() const { return _upstream; }

            RouterID downstream() { return _downstream; }
            const RouterID& downstream() const { return _downstream; }

            HopID rxid() { return _rxid; }
            const HopID& rxid() const { return _rxid; }

            HopID txid() { return _txid; }
            const HopID& txid() const { return _txid; }

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

            bool operator!=(const TransitHop& other) const { return !(*this == other); }

            std::chrono::milliseconds last_activity() const { return _last_activity; }

            bool is_expired(std::chrono::milliseconds now = llarp::time_now_ms()) const { return now >= expiry; };

            nlohmann::json ExtractStatus() const;

            std::string to_string() const;
            static constexpr bool to_string_formattable = true;
        };
    }  // namespace path
}  // namespace llarp
