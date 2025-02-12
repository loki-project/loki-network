#pragma once

#include "path_handler.hpp"
#include "transit_hop.hpp"

#include <llarp/constants/path.hpp>
#include <llarp/contact/client_contact.hpp>
#include <llarp/contact/tag.hpp>
#include <llarp/crypto/types.hpp>
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

    namespace service
    {
        struct EncryptedIntroSet;
    }

    namespace path
    {
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

            std::weak_ptr<PathHandler> handler;
            ClientIntro intro{};

            std::shared_ptr<Path> get_self() { return shared_from_this(); }

            std::weak_ptr<Path> get_weak() { return weak_from_this(); }

            nlohmann::json ExtractStatus() const;

            std::string hop_string() const;

            std::chrono::milliseconds LastRemoteActivityAt() const { return last_recv_msg; }

            void set_established();

            // void recv_path_data_message(bstring data);

            void link_session(session_tag t);

            bool unlink_session(session_tag t);

            bool is_linked_to(session_tag t) const;

            bool is_linked() const { return not _linked_sessions.empty(); }

            bool is_expired(std::chrono::milliseconds now = llarp::time_now_ms()) const;

            void Tick(std::chrono::milliseconds now);

            bool resolve_sns(std::string_view name, bt_control_response_hook func);

            bool find_client_contact(const hash_key& location, bt_control_response_hook func);

            bool publish_client_contact(const EncryptedClientContact& ecc, bt_control_response_hook func);

            /// sends a control request along a path
            ///
            /// performs the necessary onion encryption before sending.
            /// func will be called when a timeout occurs or a response is received.
            /// if a response is received, onion decryption is performed before func is called.
            ///
            /// func is called with a bt-encoded response string (if applicable), and
            /// a timeout flag (if set, response string will be empty)
            bool send_path_control_message(std::string method, std::string body, bt_control_response_hook func);

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

            std::unordered_set<session_tag> _linked_sessions;

            std::chrono::milliseconds last_recv_msg{0s};
            std::chrono::milliseconds last_latency_test{0s};
            uint64_t last_latency_test_id{};
        };

        struct PathPtrComp
        {
            bool operator()(const std::shared_ptr<Path>& lhs, const std::shared_ptr<Path>& rhs) const
            {
                return *lhs < *rhs;
            }
        };

        using PathPtrSet = std::set<std::shared_ptr<Path>, PathPtrComp>;

    }  // namespace path
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::path::Path>
    {
        size_t operator()(const llarp::path::Path& p) const noexcept
        {
            return hash<llarp::HopID>{}(p.pivot_txid()) ^ ((hash<llarp::HopID>{}(p.upstream_rxid()) << 13) >> 5);
        }
    };
}  //  namespace std
