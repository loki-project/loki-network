#pragma once

#include "path_handler.hpp"
#include "transit_hop.hpp"

#include <llarp/constants/path.hpp>
#include <llarp/contact/client_contact.hpp>
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
    struct Profiling;

    // namespace link
    // {
    //     struct LinkManager;
    // }

    namespace service
    {
        struct EncryptedIntroSet;
    }

    namespace path
    {
        using recv_session_dgram_cb = std::function<void(bstring data)>;

        /** TODO:
                - we only need a vector of RID's for path-building, not RemoteRC's
         */

        /// A path we made
        struct Path : public std::enable_shared_from_this<Path>
        {
            friend struct PathHandler;
            friend class handlers::SessionEndpoint;
            friend struct llarp::Profiling;
            friend struct LinkManager;

            Path(
                Router& rtr,
                const std::vector<RemoteRC>& routers,
                std::weak_ptr<PathHandler> parent,
                bool is_session = false,
                bool is_client = false);

            // hops on constructed path
            std::vector<TransitHop> hops;
            // local hop info for onioned responses and session messages
            // std::shared_ptr<TransitHop> _local_hop{};
            std::weak_ptr<PathHandler> handler;
            ClientIntro intro{};

            std::shared_ptr<Path> get_self() { return shared_from_this(); }

            std::weak_ptr<Path> get_weak() { return weak_from_this(); }

            nlohmann::json ExtractStatus() const;

            std::string hop_string() const;

            std::chrono::milliseconds LastRemoteActivityAt() const { return last_recv_msg; }

            void set_established();

            void recv_path_data_message(bstring data);

            void link_session(recv_session_dgram_cb cb);

            bool unlink_session();

            bool is_linked() const { return _is_linked; }

            void enable_exit_traffic();

            void mark_exit_closed();

            bool update_exit(uint64_t tx_id);

            bool is_expired(std::chrono::milliseconds now = llarp::time_now_ms()) const;

            void Tick(std::chrono::milliseconds now);

            bool resolve_sns(std::string_view name, std::function<void(oxen::quic::message)> func);

            bool find_client_contact(const dht::Key_t& location, std::function<void(oxen::quic::message)> func);

            bool publish_client_contact(
                const EncryptedClientContact& ecc, std::function<void(oxen::quic::message)> func);

            bool close_exit(
                const Ed25519SecretKey& sk, std::string tx_id, std::function<void(oxen::quic::message)> = nullptr);

            bool obtain_exit(
                const Ed25519SecretKey& sk,
                uint64_t flag,
                std::string tx_id,
                std::function<void(oxen::quic::message)> func);

            /// sends a control request along a path
            ///
            /// performs the necessary onion encryption before sending.
            /// func will be called when a timeout occurs or a response is received.
            /// if a response is received, onion decryption is performed before func is called.
            ///
            /// func is called with a bt-encoded response string (if applicable), and
            /// a timeout flag (if set, response string will be empty)
            bool send_path_control_message(
                std::string method, std::string body, std::function<void(oxen::quic::message)> func);

            bool send_path_data_message(std::string body);

            std::string make_path_message(std::string payload);

            bool is_established() const { return _established; }

            bool is_ready(std::chrono::milliseconds now = llarp::time_now_ms()) const;

            std::shared_ptr<PathHandler> get_parent();

            TransitHop edge() const;

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

            std::string to_string() const;
            static constexpr bool to_string_formattable = true;

          protected:
            void populate_internals(const std::vector<RemoteRC>& _hops);

            /// call obtained exit hooks
            bool InformExitResult(std::chrono::milliseconds b);

            std::atomic<bool> _established{false};
            std::atomic<bool> _is_linked{false};

            Router& _router;

            bool _is_session_path{false};
            bool _is_client{false};

            const size_t num_hops;

            recv_session_dgram_cb _recv_dgram;

            std::chrono::milliseconds last_recv_msg{0s};
            std::chrono::milliseconds last_latency_test{0s};
            uint64_t last_latency_test_id{};
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
            auto h = hash<llarp::HopID>{}(p.upstream_txid());
            return h ^ hash<llarp::RouterID>{}(p.upstream_rid());
        }
    };
}  //  namespace std
