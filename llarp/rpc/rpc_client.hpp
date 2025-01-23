#pragma once

#include <llarp/contact/router_id.hpp>
#include <llarp/contact/sns.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/dht/key.hpp>
#include <llarp/ev/types.hpp>

#include <oxenmq/address.h>
#include <oxenmq/oxenmq.h>

namespace llarp
{
    struct Router;

    namespace rpc
    {
        inline constexpr auto PING_INTERVAL{30s};

        /// The LokidRpcClient uses loki-mq to talk to make API requests to lokid.
        struct RPCClient : public std::enable_shared_from_this<RPCClient>
        {
            explicit RPCClient(std::shared_ptr<oxenmq::OxenMQ> lmq, std::weak_ptr<Router> r);

            /// Connect to lokid async
            void connect_async(oxenmq::address url);

            /// blocking request identity key from lokid
            /// throws on failure
            Ed25519SecretKey obtain_identity_key();

            /// get what the current block height is according to oxend
            uint64_t block_height() const { return _block_height; }

            void lookup_ons_hash(
                std::string namehash, std::function<void(std::optional<EncryptedSNSRecord>)> resultHandler);

            /// inform that if connected to a router successfully
            void inform_connection(RouterID router, bool success);

            void start_pings();

          private:
            /// do a lmq command on the current connection
            void command(std::string_view cmd);

            /// triggers a service node list refresh from oxend; thread-safe and will do nothing if
            /// an update is already in progress.
            void update_service_node_list();

            template <typename HandlerFunc_t, typename Args_t>
            void request(std::string_view cmd, HandlerFunc_t func, const Args_t& args)
            {
                _omq->request(*_conn, std::move(cmd), std::move(func), args);
            }

            template <typename HandlerFunc_t>
            void request(std::string_view cmd, HandlerFunc_t func)
            {
                _omq->request(*_conn, std::move(cmd), std::move(func));
            }

            // Handles a service node list update; takes the "service_node_states" object of an
            // oxend "get_service_nodes" rpc request.
            void handle_new_service_node_list(const nlohmann::json& json);

            // Handles notification of a new block
            void handle_new_block(oxenmq::Message& msg);

            std::shared_ptr<EventTicker> _ping_ticker;

            std::optional<oxenmq::ConnectionID> _conn;
            std::shared_ptr<oxenmq::OxenMQ> _omq;

            std::weak_ptr<Router> _router;
            std::atomic<bool> _is_updating_list;
            std::string _last_hash_update;

            std::unordered_map<RouterID, PubKey> _key_map;

            uint64_t _block_height;
        };

    }  // namespace rpc
}  // namespace llarp
