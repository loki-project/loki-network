#include "rpc_client.hpp"

#include <llarp/router/router.hpp>
#include <llarp/util/logging.hpp>

#include <nlohmann/json.hpp>
#include <oxenc/hex.h>

#include <stdexcept>

namespace llarp::rpc
{
    static auto logcat = log::Cat("rpc.client");

    static constexpr oxenmq::LogLevel toLokiMQLogLevel(log::Level level)
    {
        switch (level)
        {
            case log::Level::critical:
                return oxenmq::LogLevel::fatal;
            case log::Level::err:
                return oxenmq::LogLevel::error;
            case log::Level::warn:
                return oxenmq::LogLevel::warn;
            case log::Level::info:
                return oxenmq::LogLevel::info;
            case log::Level::debug:
                return oxenmq::LogLevel::debug;
            case log::Level::trace:
            case log::Level::off:
            default:
                return oxenmq::LogLevel::trace;
        }
    }

    RPCClient::RPCClient(std::shared_ptr<oxenmq::OxenMQ> lmq, std::weak_ptr<Router> r)
        : m_lokiMQ{std::move(lmq)}, _router{std::move(r)}
    {
        // m_lokiMQ->log_level(toLokiMQLogLevel(LogLevel::Instance().curLevel));

        // new block handler
        m_lokiMQ->add_category("notify", oxenmq::Access{oxenmq::AuthLevel::none})
            .add_command("block", [this](oxenmq::Message& m) { handle_new_block(m); });

        // TODO: proper auth here
        auto lokidCategory = m_lokiMQ->add_category("lokid", oxenmq::Access{oxenmq::AuthLevel::none});
        _is_updating_list = false;
    }

    void RPCClient::connect_async(oxenmq::address url)
    {
        if (auto router = _router.lock())
        {
            if (not router->is_service_node())
            {
                throw std::runtime_error("we cannot talk to lokid while not a service node");
            }

            log::info(logcat, "RPC client connecting to oxend at {}", url.full_address());

            m_Connection = m_lokiMQ->connect_remote(
                url,
                [](oxenmq::ConnectionID) {},
                [self = shared_from_this(), url](oxenmq::ConnectionID, std::string_view f) {
                    log::info(logcat, "Failed to connect to oxend at {}", f);

                    if (auto router = self->_router.lock())
                    {
                        router->loop()->call([self, url]() { self->connect_async(url); });
                    }
                });
        }
    }

    void RPCClient::command(std::string_view cmd)
    {
        log::debug(logcat, "Oxend command: {}", cmd);
        m_lokiMQ->send(*m_Connection, std::move(cmd));
    }

    void RPCClient::handle_new_block(oxenmq::Message& msg)
    {
        if (msg.data.size() != 2)
        {
            log::error(
                logcat,
                "Received invalid new block notification with {} parts (expected 2); not updating service node list!",
                msg.data.size());

            return;  // bail
        }
        try
        {
            _block_height = std::stoll(std::string{msg.data[0]});
        }
        catch (std::exception& ex)
        {
            log::error(logcat, "Bad block height: {}", ex.what());

            return;  // bail
        }

        log::trace(logcat, "new block at height {}", _block_height);
        // don't upadate on block notification if an update is pending
        if (not _is_updating_list)
            update_service_node_list();
    }

    void RPCClient::update_service_node_list()
    {
        if (_is_updating_list.exchange(true))
            return;  // update already in progress

        nlohmann::json req{
            {"fields",
             {
                 {"pubkey_ed25519", true},
                 {"service_node_pubkey", true},
                 {"funded", true},
                 {"active", true},
                 {"block_hash", true},
             }},
        };
        if (!_last_hash_update.empty())
            req["poll_block_hash"] = _last_hash_update;

        request(
            "rpc.get_service_nodes",
            [self = shared_from_this()](bool success, std::vector<std::string> data) {
                if (not success)
                    log::warning(logcat, "Failed to update service node list");
                else if (data.size() < 2)
                    log::warning(logcat, "Oxend gave empty reply for service node list");
                else
                {
                    try
                    {
                        auto json = nlohmann::json::parse(std::move(data[1]));
                        if (json.at("status") != "OK")
                            throw std::runtime_error{"get_service_nodes did not return 'OK' status"};
                        if (auto it = json.find("unchanged"); it != json.end() and it->is_boolean() and it->get<bool>())
                            log::trace(logcat, "service node list unchanged");
                        else
                        {
                            self->handle_new_service_node_list(json.at("service_node_states"));
                            if (auto it = json.find("block_hash"); it != json.end() and it->is_string())
                                self->_last_hash_update = it->get<std::string>();
                            else
                                self->_last_hash_update.clear();
                        }
                    }
                    catch (const std::exception& ex)
                    {
                        log::error(logcat, "Failed to process service node list: {}", ex.what());
                    }
                }

                // set down here so that the 1) we don't start updating until we're completely
                // finished with the previous update; and 2) so that m_UpdatingList also guards
                // m_LastUpdateHash
                self->_is_updating_list = false;
            },
            req.dump());
    }

    void RPCClient::start_pings()
    {
        constexpr auto PingInterval = 30s;

        auto router = _router.lock();
        if (not router)
            return;

        auto makePingRequest = router->loop()->make_caller([self = shared_from_this()]() {
            // send a ping
            PubKey pk{};
            auto r = self->_router.lock();
            if (not r)
                return;  // router has gone away, maybe shutting down?

            pk = r->local_rid();

            nlohmann::json payload = {
                {"pubkey_ed25519", oxenc::to_hex(pk.begin(), pk.end())},
                {"version", {LOKINET_VERSION[0], LOKINET_VERSION[1], LOKINET_VERSION[2]}}};

            if (auto err = r->OxendErrorState())
                payload["error"] = *err;

            self->request(
                "admin.lokinet_ping",
                [](bool success, std::vector<std::string> data) {
                    (void)data;
                    log::debug(logcat, "Received response for ping. Successful: {}", success);
                },
                payload.dump());

            // subscribe to block updates
            self->request("sub.block", [](bool success, std::vector<std::string> data) {
                if (data.empty() or not success)
                {
                    log::error(logcat, "Failed to subscribe to new blocks");
                    return;
                }
                log::debug(logcat, "Subscribed to new blocks: {}", data[0]);
            });
            // Trigger an update on a regular timer as well in case we missed a block notify for
            // some reason (e.g. oxend restarts and loses the subscription); we poll using the last
            // known hash so that the poll is very cheap (basically empty) if the block hasn't
            // advanced.
            self->update_service_node_list();
        });

        // Fire one ping off right away to get things going.
        makePingRequest();
        m_lokiMQ->add_timer(std::move(makePingRequest), PingInterval);
    }

    void RPCClient::handle_new_service_node_list(const nlohmann::json& j)
    {
        std::unordered_map<RouterID, PubKey> keymap;
        std::vector<RouterID> activeNodeList, decommNodeList, unfundedNodeList;
        if (not j.is_array())
            throw std::runtime_error{"Invalid service node list: expected array of service node states"};

        for (auto& snode : j)
        {
            const auto ed_itr = snode.find("pubkey_ed25519");
            if (ed_itr == snode.end() or not ed_itr->is_string())
                continue;
            const auto svc_itr = snode.find("service_node_pubkey");
            if (svc_itr == snode.end() or not svc_itr->is_string())
                continue;
            const auto active_itr = snode.find("active");
            if (active_itr == snode.end() or not active_itr->is_boolean())
                continue;
            const bool active = active_itr->get<bool>();
            const auto funded_itr = snode.find("funded");
            if (funded_itr == snode.end() or not funded_itr->is_boolean())
                continue;
            const bool funded = funded_itr->get<bool>();

            RouterID rid;
            PubKey pk;
            if (not rid.FromHex(ed_itr->get<std::string_view>()) or not pk.FromHex(svc_itr->get<std::string_view>()))
                continue;

            keymap[rid] = pk;
            (active ? activeNodeList : funded ? decommNodeList : unfundedNodeList).push_back(std::move(rid));
        }

        if (activeNodeList.empty())
        {
            log::warning(logcat, "Received empty service node list, ignoring.");
            return;
        }

        // inform router about the new list
        if (auto router = _router.lock())
        {
            auto& loop = router->loop();
            loop->call([this,
                        active = std::move(activeNodeList),
                        decomm = std::move(decommNodeList),
                        unfunded = std::move(unfundedNodeList),
                        keymap = std::move(keymap),
                        router = std::move(router)]() mutable {
                _key_map = std::move(keymap);

                router->set_router_whitelist(active, decomm, unfunded);
            });
        }
        else
            log::warning(logcat, "Cannot update whitelist: router object has gone away");
    }

    void RPCClient::inform_connection(RouterID router, bool success)
    {
        if (auto r = _router.lock())
        {
            r->loop()->call([router, success, this]() {
                if (auto itr = _key_map.find(router); itr != _key_map.end())
                {
                    const nlohmann::json req = {
                        {"passed", success}, {"pubkey", itr->second.ToHex()}, {"type", "lokinet"}};
                    request(
                        "admin.report_peer_status",
                        [self = shared_from_this()](bool success, std::vector<std::string>) {
                            if (not success)
                            {
                                log::error(logcat, "Failed to report connection status to oxend");
                                return;
                            }
                            log::debug(logcat, "Reported connection status to core");
                        },
                        req.dump());
                }
            });
        }
    }

    SecretKey RPCClient::obtain_identity_key()
    {
        std::promise<SecretKey> promise;
        request(
            "admin.get_service_privkeys",
            [self = shared_from_this(), &promise](bool success, std::vector<std::string> data) {
                try
                {
                    if (not success)
                        throw std::runtime_error("Failed to get private key request");

                    if (data.empty() or data.size() < 2)
                        throw std::runtime_error("Failed to get private key request: data empty");

                    const auto j = nlohmann::json::parse(data[1]);
                    SecretKey k;

                    if (not k.FromHex(j.at("service_node_ed25519_privkey").get<std::string>()))
                        throw std::runtime_error("failed to parse private key");

                    promise.set_value(k);
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Caught exception while trying to request admin keys: {}", e.what());
                    promise.set_exception(std::current_exception());
                }
                catch (...)
                {
                    log::warning(logcat, "Caught non-standard exception while trying to request admin keys");
                    promise.set_exception(std::current_exception());
                }
            });

        auto ftr = promise.get_future();
        return ftr.get();
    }

    void RPCClient::lookup_ons_hash(
        std::string namehash, std::function<void(std::optional<service::EncryptedONSRecord>)> resultHandler)
    {
        log::debug(logcat, "Looking Up ONS NameHash {}", namehash);
        const nlohmann::json req{{"type", 2}, {"name_hash", oxenc::to_hex(namehash)}};
        request(
            "rpc.lns_resolve",
            [this, resultHandler](bool success, std::vector<std::string> data) {
                std::optional<service::EncryptedONSRecord> maybe = std::nullopt;
                if (success)
                {
                    try
                    {
                        service::EncryptedONSRecord result;
                        const auto j = nlohmann::json::parse(data[1]);
                        j.dump();
                        result.ciphertext = oxenc::from_hex(j["encrypted_value"].get<std::string>());
                        const auto nonce = oxenc::from_hex(j["nonce"].get<std::string>());
                        if (nonce.size() != result.nonce.size())
                        {
                            throw std::invalid_argument{
                                fmt::format("nonce size mismatch: {} != {}", nonce.size(), result.nonce.size())};
                        }

                        std::copy_n(nonce.data(), nonce.size(), result.nonce.data());
                        maybe = result;
                    }
                    catch (std::exception& ex)
                    {
                        log::error(logcat, "Failed to parse response from ONS lookup: {}", ex.what());
                    }
                }
                if (auto r = _router.lock())
                {
                    r->loop()->call([resultHandler, maybe = std::move(maybe)]() { resultHandler(std::move(maybe)); });
                }
            },
            req.dump());
    }

}  // namespace llarp::rpc
