#pragma once

#include "path_handler.hpp"

#include <llarp/constants/path.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/dht/key.hpp>
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

    namespace service
    {
        struct EncryptedIntroSet;
    }

    namespace path
    {
        struct TransitHop;
        struct PathHopConfig;

        using recv_session_dgram_cb = std::function<void(bstring data)>;

        // TODO: replace vector of PathHopConfig with vector of TransitHops

        /// A path we made
        struct Path : public std::enable_shared_from_this<Path>
        {
            std::vector<PathHopConfig> hops;

            std::weak_ptr<PathHandler> handler;

            service::Introduction intro;

            std::chrono::milliseconds buildStarted = 0s;

            Path(
                Router& rtr,
                const std::vector<RemoteRC>& routers,
                std::weak_ptr<PathHandler> parent,
                bool is_session = false,
                bool is_client = false);

            std::shared_ptr<Path> get_self() { return shared_from_this(); }

            std::weak_ptr<Path> get_weak() { return weak_from_this(); }

            nlohmann::json ExtractStatus() const;

            std::string to_string() const;

            std::string HopsString() const;

            std::chrono::milliseconds LastRemoteActivityAt() const { return last_recv_msg; }

            void set_established() { _established = true; }

            void recv_path_data_message(bstring data);

            void link_session(recv_session_dgram_cb cb);

            bool unlink_session();

            bool is_linked() const { return _is_linked; }

            std::chrono::milliseconds ExpireTime() const { return buildStarted + hops[0].lifetime; }

            bool ExpiresSoon(std::chrono::milliseconds now, std::chrono::milliseconds dlt = 5s) const
            {
                return now >= (ExpireTime() - dlt);
            }

            void enable_exit_traffic();

            void mark_exit_closed();

            bool update_exit(uint64_t tx_id);

            bool is_expired(std::chrono::milliseconds now) const;

            /// build a new path on the same set of hops as us
            /// regenerates keys
            void rebuild();

            void Tick(std::chrono::milliseconds now);

            bool resolve_ons(std::string name, std::function<void(std::string)> func = nullptr);

            bool find_intro(
                const dht::Key_t& location,
                bool is_relayed = false,
                uint64_t order = 0,
                std::function<void(std::string)> func = nullptr);

            bool publish_intro(
                const service::EncryptedIntroSet& introset,
                bool is_relayed = false,
                uint64_t order = 0,
                std::function<void(std::string)> func = nullptr);

            bool close_exit(
                const Ed25519SecretKey& sk, std::string tx_id, std::function<void(std::string)> func = nullptr);

            bool obtain_exit(
                const Ed25519SecretKey& sk,
                uint64_t flag,
                std::string tx_id,
                std::function<void(std::string)> func = nullptr);

            /// sends a control request along a path
            ///
            /// performs the necessary onion encryption before sending.
            /// func will be called when a timeout occurs or a response is received.
            /// if a response is received, onion decryption is performed before func is called.
            ///
            /// func is called with a bt-encoded response string (if applicable), and
            /// a timeout flag (if set, response string will be empty)
            bool send_path_control_message(
                std::string method, std::string body, std::function<void(std::string)> func = nullptr);

            bool send_path_data_message(std::string body);

            bool is_ready() const;

            RouterID upstream_rid();
            const RouterID& upstream_rid() const;

            HopID upstream_rxid();
            const HopID& upstream_rxid() const;

            HopID upstream_txid();
            const HopID& upstream_txid() const;

            RouterID pivot_rid();
            const RouterID& pivot_rid() const;

            HopID pivot_rxid();
            const HopID& pivot_rxid() const;

            HopID pivot_txid();
            const HopID& pivot_txid() const;

            std::string name() const;

            bool is_session_path() const { return _is_session_path; }

            bool is_client_path() const { return _is_client; }

            bool operator<(const Path& other) const;

            bool operator==(const Path& other) const;

            bool operator!=(const Path& other) const;

            static constexpr bool to_string_formattable = true;

          private:
            std::string make_outer_payload(ustring_view payload);

            std::string make_outer_payload(ustring_view payload, SymmNonce& nonce);

            bool SendLatencyMessage(Router* r);

            /// call obtained exit hooks
            bool InformExitResult(std::chrono::milliseconds b);

            std::atomic<bool> _established{false};
            std::atomic<bool> _is_linked{false};

            Router& _router;

            bool _is_session_path{false};
            bool _is_client{false};

            recv_session_dgram_cb _recv_dgram;

            std::chrono::milliseconds last_recv_msg = 0s;
            std::chrono::milliseconds last_latency_test = 0s;
            uint64_t last_latency_test_id = 0;
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
