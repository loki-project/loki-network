#pragma once

#include "abstracthophandler.hpp"
#include "pathhandler.hpp"

#include <llarp/constants/path.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/dht/key.hpp>
#include <llarp/router_id.hpp>
#include <llarp/service/intro.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/util/thread/threading.hpp>
#include <llarp/util/time.hpp>

#include <algorithm>
#include <functional>
#include <list>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace llarp
{
    struct Router;

    /*
      TODO:
        - Add a boolean for "allow incoming session" or something
    */

    namespace path
    {
        struct TransitHop;
        struct TransitHopInfo;
        struct PathHopConfig;

        /// A path we made
        struct Path final : public AbstractHopHandler, public std::enable_shared_from_this<Path>
        {
            std::vector<PathHopConfig> hops;

            std::weak_ptr<PathHandler> handler;

            service::Introduction intro;

            llarp_time_t buildStarted = 0s;

            Path(
                Router& rtr,
                const std::vector<RemoteRC>& routers,
                std::weak_ptr<PathHandler> parent,
                std::string shortName);

            std::shared_ptr<Path> get_self()
            {
                return shared_from_this();
            }

            std::weak_ptr<Path> get_weak()
            {
                return weak_from_this();
            }

            StatusObject ExtractStatus() const;

            void MarkActive(llarp_time_t now)
            {
                last_recv_msg = std::max(now, last_recv_msg);
            }

            const std::string& short_name() const;

            std::string HopsString() const;

            llarp_time_t LastRemoteActivityAt() const override
            {
                return last_recv_msg;
            }

            // TODO: make this into multiple functions and fuck PathStatus forever
            void set_established()
            {
                _established = true;
            }

            llarp_time_t ExpireTime() const
            {
                return buildStarted + hops[0].lifetime;
            }

            bool ExpiresSoon(llarp_time_t now, llarp_time_t dlt = 5s) const override
            {
                return now >= (ExpireTime() - dlt);
            }

            void enable_exit_traffic()
            {
                log::info(path_cat, "{} {} granted exit", name(), pivot_router_id());
                // _role |= ePathRoleExit;
            }

            void mark_exit_closed()
            {
                log::info(path_cat, "{} hd its exit closed", name());
                // _role &= ePathRoleExit;
            }

            bool update_exit(uint64_t tx_id);

            bool is_expired(llarp_time_t now) const override;

            /// build a new path on the same set of hops as us
            /// regenerates keys
            void rebuild();

            void Tick(llarp_time_t now, Router* r);

            bool find_name(std::string name, std::function<void(std::string)> func = nullptr);

            bool find_intro(
                const dht::Key_t& location,
                bool is_relayed = false,
                uint64_t order = 0,
                std::function<void(std::string)> func = nullptr);

            bool close_exit(SecretKey sk, std::string tx_id, std::function<void(std::string)> func = nullptr);

            bool obtain_exit(
                SecretKey sk, uint64_t flag, std::string tx_id, std::function<void(std::string)> func = nullptr);

            /// sends a control request along a path
            ///
            /// performs the necessary onion encryption before sending.
            /// func will be called when a timeout occurs or a response is received.
            /// if a response is received, onion decryption is performed before func is called.
            ///
            /// func is called with a bt-encoded response string (if applicable), and
            /// a timeout flag (if set, response string will be empty)
            bool send_path_control_message(
                std::string method, std::string body, std::function<void(std::string)> func = nullptr) override;

            bool send_path_data_message(std::string body) override;

            bool IsReady() const;

            // Is this deprecated?
            // nope not deprecated :^DDDD
            HopID TXID() const;

            RouterID pivot_router_id() const;

            HopID RXID() const override;

            RouterID upstream() const;

            std::string name() const;

            bool operator<(const Path& other) const;

            bool operator==(const Path& other) const;

            bool operator!=(const Path& other) const;

          private:
            std::string make_outer_payload(std::string payload);

            bool SendLatencyMessage(Router* r);

            /// call obtained exit hooks
            bool InformExitResult(llarp_time_t b);

            std::atomic<bool> _established{false};

            Router& _router;
            llarp_time_t last_recv_msg = 0s;
            llarp_time_t last_latency_test = 0s;
            uint64_t last_latency_test_id = 0;
            const std::string _short_name;
        };
    }  // namespace path
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::path::Path>
    {
        size_t operator()(const llarp::path::Path& p) const
        {
            auto& first_hop = p.hops[0];
            llarp::AlignedBuffer<PUBKEYSIZE> b;
            std::memcpy(b.data(), first_hop.txID.data(), PATHIDSIZE);
            std::memcpy(&b[PATHIDSIZE], first_hop.txID.data(), PATHIDSIZE);

            auto h = hash<llarp::AlignedBuffer<PUBKEYSIZE>>{}(b);
            return h ^ hash<llarp::RouterID>{}(first_hop.upstream);
        }
    };
}  //  namespace std
