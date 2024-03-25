#pragma once

#include <llarp/constants/path.hpp>
#include <llarp/path/abstracthophandler.hpp>
#include <llarp/path/path_types.hpp>
#include <llarp/router_id.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/thread/queue.hpp>

namespace llarp
{
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

        struct TransitHop : public AbstractHopHandler, std::enable_shared_from_this<TransitHop>
        {
            TransitHop();

            TransitHopInfo info;
            SharedSecret pathKey;
            SymmNonce nonceXOR;
            std::chrono::milliseconds started = 0s;
            // 10 minutes default
            std::chrono::milliseconds lifetime = DEFAULT_LIFETIME;
            uint8_t version;
            std::chrono::milliseconds last_activity = 0s;
            bool terminal_hop{false};

            // If randomize is given, first randomizes `nonce`
            //
            // Does xchacha20 on `data` in-place with `nonce` and `pathKey`, then
            // mutates `nonce` = `nonce` ^ `nonceXOR` in-place.
            void onion(ustring& data, SymmNonce& nonce, bool randomize = false) const;

            void onion(std::string& data, SymmNonce& nonce, bool randomize = false) const;

            std::string onion_and_payload(
                std::string& payload, HopID next_id, std::optional<SymmNonce> nonce = std::nullopt) const;

            HopID RXID() const override
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

            std::chrono::milliseconds LastRemoteActivityAt() const override
            {
                return last_activity;
            }

            std::string to_string() const;

            bool is_expired(std::chrono::milliseconds now) const override;

            bool ExpiresSoon(std::chrono::milliseconds now, std::chrono::milliseconds dlt) const override
            {
                return now >= ExpireTime() - dlt;
            }

            // TODO: should this be a separate method indicating directionality?
            //       Most control messages won't make sense to be sent to a client,
            //       so perhaps control messages from a terminal relay to a client (rather than
            //       the other way around) should be their own message type.
            //
            /// sends a control request along a path
            ///
            /// performs the necessary onion encryption before sending.
            /// func will be called when a timeout occurs or a response is received.
            /// if a response is received, onion decryption is performed before func is called.
            ///
            /// func is called with a bt-encoded response string (if applicable), and
            /// a timeout flag (if set, response string will be empty)
            bool send_path_control_message(
                std::string method, std::string body, std::function<void(std::string)> func) override;
            bool send_path_data_message(std::string body) override;

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
