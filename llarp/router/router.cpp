#include "router.hpp"

#include <llarp/config/config.hpp>
#include <llarp/constants/proto.hpp>
#include <llarp/constants/time.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dht/node.hpp>
#include <llarp/ev/ev.hpp>
#include <llarp/link/contacts.hpp>
#include <llarp/link/link_manager.hpp>
#include <llarp/messages/dht.hpp>
#include <llarp/net/net.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/status.hpp>

#include <cstdlib>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#if defined(ANDROID) || defined(IOS)
#include <unistd.h>
#endif

#if defined(WITH_SYSTEMD)
#include <systemd/sd-daemon.h>
#endif

#include <llarp/constants/platform.hpp>

#include <oxenmq/oxenmq.h>

static constexpr std::chrono::milliseconds ROUTER_TICK_INTERVAL = 250ms;

namespace llarp
{
    Router::Router(EventLoop_ptr loop, std::shared_ptr<vpn::Platform> vpnPlatform)
        : _route_poker{std::make_shared<RoutePoker>(*this)},
          _lmq{std::make_shared<oxenmq::OxenMQ>()},
          _loop{std::move(loop)},
          _vpn{std::move(vpnPlatform)},
          paths{this},
          _exit_context{this},
          _disk_thread{_lmq->add_tagged_thread("disk")},
          _rpc_server{nullptr},
          _randomStartDelay{platform::is_simulation ? std::chrono::milliseconds{(llarp::randint() % 1250) + 2000} : 0s}
          // , _link_manager{*this}
          ,
          _hidden_service_context{this}
    {
        _key_manager = std::make_shared<KeyManager>();
        // for lokid, so we don't close the connection when syncing the whitelist
        _lmq->MAX_MSG_SIZE = -1;
        is_stopping.store(false);
        is_running.store(false);
        _last_tick = llarp::time_now_ms();
        _next_explore_at = std::chrono::steady_clock::now();
        loop_wakeup = _loop->make_waker([this]() { PumpLL(); });
    }

    // TODO: investigate changes needed for libquic integration
    //       still needed at all?
    // TODO: No. The answer is No.
    // TONUKE: EVERYTHING ABOUT THIS
    void Router::PumpLL()
    {
        llarp::LogTrace("Router::PumpLL() start");
        if (is_stopping.load())
            return;
        _hidden_service_context.Pump();
        llarp::LogTrace("Router::PumpLL() end");
    }

    util::StatusObject Router::ExtractStatus() const
    {
        if (not is_running)
            util::StatusObject{{"running", false}};

        return util::StatusObject{
            {"running", true},
            {"numNodesKnown", _node_db->num_rcs()},
            {"services", _hidden_service_context.ExtractStatus()},
            {"exit", _exit_context.ExtractStatus()},
            {"links", _link_manager->extract_status()}};
    }

    // TODO: investigate changes needed for libquic integration
    util::StatusObject Router::ExtractSummaryStatus() const
    {
        if (!is_running)
            return util::StatusObject{{"running", false}};

        auto services = _hidden_service_context.ExtractStatus();

        auto link_types = _link_manager->extract_status();

        uint64_t tx_rate = 0;
        uint64_t rx_rate = 0;
        uint64_t peers = 0;
        for (const auto& links : link_types)
        {
            for (const auto& link : links)
            {
                if (link.empty())
                    continue;
                for (const auto& peer : link["sessions"]["established"])
                {
                    tx_rate += peer["tx"].get<uint64_t>();
                    rx_rate += peer["rx"].get<uint64_t>();
                    peers++;
                }
            }
        }

        // Compute all stats on all path builders on the default endpoint
        // Merge snodeSessions, remoteSessions and default into a single array
        std::vector<nlohmann::json> builders;

        if (services.is_object())
        {
            const auto& serviceDefault = services.at("default");
            builders.push_back(serviceDefault);

            auto snode_sessions = serviceDefault.at("snodeSessions");
            for (const auto& session : snode_sessions)
                builders.push_back(session);

            auto remote_sessions = serviceDefault.at("remoteSessions");
            for (const auto& session : remote_sessions)
                builders.push_back(session);
        }

        // Iterate over all items on this array to build the global pathStats
        uint64_t pathsCount = 0;
        uint64_t success = 0;
        uint64_t attempts = 0;
        for (const auto& builder : builders)
        {
            if (builder.is_null())
                continue;

            const auto& paths = builder.at("paths");
            if (paths.is_array())
            {
                for (const auto& [key, value] : paths.items())
                {
                    if (value.is_object() && value.at("status").is_string() && value.at("status") == "established")
                        pathsCount++;
                }
            }

            const auto& buildStats = builder.at("buildStats");
            if (buildStats.is_null())
                continue;

            success += buildStats.at("success").get<uint64_t>();
            attempts += buildStats.at("attempts").get<uint64_t>();
        }
        double ratio = static_cast<double>(success) / (attempts + 1);

        util::StatusObject stats{
            {"running", true},
            {"version", llarp::LOKINET_VERSION_FULL},
            {"uptime", to_json(Uptime())},
            {"numPathsBuilt", pathsCount},
            {"numPeersConnected", peers},
            {"numRoutersKnown", _node_db->num_rcs()},
            {"ratio", ratio},
            {"txRate", tx_rate},
            {"rxRate", rx_rate},
        };

        if (services.is_object())
        {
            stats["authCodes"] = services["default"]["authCodes"];
            stats["exitMap"] = services["default"]["exitMap"];
            stats["networkReady"] = services["default"]["networkReady"];
            stats["lokiAddress"] = services["default"]["identity"];
        }
        return stats;
    }

    bool Router::fully_meshed() const
    {
        return num_router_connections() >= _node_db->num_rcs();
    }

    bool Router::needs_initial_fetch() const
    {
        return _node_db->needs_initial_fetch();
    }

    bool Router::needs_rebootstrap() const
    {
        return _node_db->needs_rebootstrap();
    }

    void Router::Freeze()
    {
        if (is_service_node())
            return;

        for_each_connection([this](link::Connection& conn) { loop()->call([&]() { conn.conn->close_connection(); }); });
    }

    void Router::Thaw()
    {
        if (is_service_node())
            return;

        std::unordered_set<RouterID> peer_pubkeys;

        for_each_connection([&peer_pubkeys](link::Connection& conn) { peer_pubkeys.emplace(conn.conn->remote_key()); });

        loop()->call([this, &peer_pubkeys]() {
            for (auto& pk : peer_pubkeys)
                _link_manager->close_connection(pk);
        });
    }

    void Router::persist_connection_until(const RouterID& remote, llarp_time_t until)
    {
        _link_manager->set_conn_persist(remote, until);
    }

    std::optional<RouterID> Router::GetRandomGoodRouter()
    {
        if (is_service_node())
            return node_db()->get_random_whitelist_router();

        if (auto maybe = node_db()->get_random_rc())
            return maybe->router_id();

        return std::nullopt;
    }

    void Router::TriggerPump()
    {
        loop_wakeup->Trigger();
    }

    bool Router::send_data_message(const RouterID& remote, std::string payload)
    {
        return _link_manager->send_data_message(remote, std::move(payload));
    }

    bool Router::send_control_message(
        const RouterID& remote, std::string ep, std::string body, std::function<void(oxen::quic::message m)> func)
    {
        return _link_manager->send_control_message(remote, std::move(ep), std::move(body), std::move(func));
    }

    void Router::for_each_connection(std::function<void(link::Connection&)> func)
    {
        return _link_manager->for_each_connection(func);
    }

    bool Router::EnsureIdentity()
    {
        _encryption = _key_manager->encryption_key;

        if (is_service_node())
        {
#if defined(ANDROID) || defined(IOS)
            LogError("running a service node on mobile device is not possible.");
            return false;
#else
#if defined(_WIN32)
            LogError("running a service node on windows is not possible.");
            return false;
#endif
#endif
            constexpr int maxTries = 5;
            int numTries = 0;
            while (numTries < maxTries)
            {
                numTries++;
                try
                {
                    _identity = rpc_client()->ObtainIdentityKey();
                    const RouterID pk{pubkey()};
                    LogWarn("Obtained lokid identity key: ", pk);
                    rpc_client()->StartPings();
                    break;
                }
                catch (const std::exception& e)
                {
                    LogWarn(
                        "Failed attempt ",
                        numTries,
                        " of ",
                        maxTries,
                        " to get lokid identity keys because: ",
                        e.what());

                    if (numTries == maxTries)
                        throw;
                }
            }
        }
        else
        {
            _identity = _key_manager->identity_key;
        }

        if (_identity.IsZero())
        {
            log::critical(logcat, "FUCK @ line:{}", __LINE__);
            return false;
        }
        if (_encryption.IsZero())
        {
            log::critical(logcat, "FUCK @ line:{}", __LINE__);
            return false;
        }

        return true;
    }

    bool Router::Configure(std::shared_ptr<Config> c, bool isSNode, std::shared_ptr<NodeDB> nodedb)
    {
        llarp::sys::service_manager->starting();

        _config = std::move(c);
        auto& conf = *_config;

        const auto& netid = conf.router.net_id;

        if (not netid.empty() and netid != llarp::LOKINET_DEFAULT_NETID)
        {
            _testnet = netid == llarp::LOKINET_TESTNET_NETID;
            _testing_disabled = conf.lokid.disable_testing;

            RouterContact::ACTIVE_NETID = netid;

            if (_testing_disabled and not _testnet)
                throw std::runtime_error{"Error: reachability testing can only be disabled on testnet!"};

            auto err = "Lokinet network ID set to {}, NOT mainnet! {}"_format(
                netid,
                _testnet ? "Please ensure your local instance is configured to operate on testnet"
                         : "Local lokinet instance will attempt to run on the specified network");
            log::critical(logcat, err);
        }

        // Backwards compat: before 0.9.10 we used `type=file` with `file=|-|stdout` for print mode
        auto log_type = conf.logging.type;

        if (log_type == log::Type::File
            && (conf.logging.file == "stdout" || conf.logging.file == "-" || conf.logging.file.empty()))
            log_type = log::Type::Print;

        if (log::get_level_default() != log::Level::off)
            log::reset_level(conf.logging.level);

        log::clear_sinks();
        log::add_sink(log_type, log_type == log::Type::System ? "lokinet" : conf.logging.file);

        // re-add rpc log sink if rpc enabled, else free it
        if (_config->api.enable_rpc_server and llarp::logRingBuffer)
            log::add_sink(llarp::logRingBuffer, llarp::log::DEFAULT_PATTERN_MONO);
        else
            llarp::logRingBuffer = nullptr;

        // TESTNET:
        // oxen::log::set_level("quic", oxen::log::Level::critical);

        log::debug(logcat, "Configuring router");

        _is_service_node = conf.router.is_relay;

        if (_is_service_node)
        {
            rpc_addr = oxenmq::address(conf.lokid.rpc_addr);
            _rpc_client = std::make_shared<rpc::LokidRpcClient>(_lmq, weak_from_this());
        }

        log::debug(logcat, "Starting RPC server");
        if (not StartRpcServer())
            throw std::runtime_error("Failed to start rpc server");

        if (conf.router.worker_threads > 0)
            _lmq->set_general_threads(conf.router.worker_threads);

        log::debug(logcat, "Starting OMQ server");
        _lmq->start();

        _node_db = std::move(nodedb);

        log::debug(logcat, _is_service_node ? "Running as a relay (service node)" : "Running as a client");

        if (_is_service_node)
            _rpc_client->ConnectAsync(rpc_addr);

        log::debug(logcat, "Initializing key manager");
        if (not _key_manager->initialize(conf, true, isSNode))
            throw std::runtime_error("KeyManager failed to initialize");

        log::debug(logcat, "Initializing from configuration");

        if (!from_config(conf))
            throw std::runtime_error("FromConfig() failed");

        log::debug(logcat, "Initializing identity");
        if (not EnsureIdentity())
            throw std::runtime_error("EnsureIdentity() failed");
        return true;
    }

    bool Router::is_service_node() const
    {
        return _is_service_node;
    }

    bool Router::insufficient_peers() const
    {
        constexpr int KnownPeerWarningThreshold = 5;
        return node_db()->num_rcs() < KnownPeerWarningThreshold;
    }

    std::optional<std::string> Router::OxendErrorState() const
    {
        // If we're in the white or gray list then we *should* be establishing connections to other
        // routers, so if we have almost no peers then something is almost certainly wrong.
        if (appears_funded() and insufficient_peers() and not _testing_disabled)
            return "too few peer connections; lokinet is not adequately connected to the network";
        return std::nullopt;
    }

    void Router::Close()
    {
        log::info(logcat, "closing");
        if (_router_close_cb)
            _router_close_cb();
        log::debug(logcat, "stopping mainloop");
        _loop->stop();
        is_running.store(false);
    }

    bool Router::have_snode_whitelist() const
    {
        return whitelist_received;
    }

    bool Router::appears_decommed() const
    {
        return _is_service_node and have_snode_whitelist() and node_db()->greylist().count(pubkey());
    }

    bool Router::appears_funded() const
    {
        return _is_service_node and have_snode_whitelist() and node_db()->is_connection_allowed(pubkey());
    }

    bool Router::appears_registered() const
    {
        return _is_service_node and have_snode_whitelist() and node_db()->registered_routers().count(pubkey());
    }

    bool Router::can_test_routers() const
    {
        return appears_funded() and not _testing_disabled;
    }

    bool Router::SessionToRouterAllowed(const RouterID& router) const
    {
        return node_db()->is_connection_allowed(router);
    }

    bool Router::PathToRouterAllowed(const RouterID& router) const
    {
        if (appears_decommed())
        {
            // we are decom'd don't allow any paths outbound at all
            return false;
        }
        return node_db()->is_path_allowed(router);
    }

    size_t Router::num_router_connections() const
    {
        return _link_manager->get_num_connected_routers();
    }

    size_t Router::num_client_connections() const
    {
        return _link_manager->get_num_connected_clients();
    }

    void Router::save_rc()
    {
        // _node_db->put_rc(router_contact.view());
        log::info(logcat, "Saving RC file to {}", our_rc_file);
        queue_disk_io([&]() { router_contact.write(our_rc_file); });
    }

    bool Router::from_config(const Config& conf)
    {
        // Set netid before anything else
        log::debug(logcat, "Network ID set to {}", conf.router.net_id);

        // Router config
        client_router_connections = conf.router.client_router_connections;

        encryption_keyfile = _key_manager->enckey_path;
        our_rc_file = _key_manager->rc_path;
        transport_keyfile = _key_manager->transkey_path;
        identity_keyfile = _key_manager->idkey_path;

        std::optional<std::string> paddr = (conf.router.public_ip) ? conf.router.public_ip
            : (conf.links.public_addr)                             ? conf.links.public_addr
                                                                   : std::nullopt;
        std::optional<uint16_t> pport = (conf.router.public_port) ? conf.router.public_port
            : (conf.links.public_port)                            ? conf.links.public_port
                                                                  : std::nullopt;

        if (pport.has_value() and not paddr.has_value())
            throw std::runtime_error{"If public-port is specified, public-addr must be as well!"};

        if (conf.links.listen_addr)
        {
            _listen_address = *conf.links.listen_addr;
        }
        else
        {
            if (paddr or pport)
                throw std::runtime_error{"Must specify [bind]:listen in config with public ip/addr!"};

            if (auto maybe_addr = net().get_best_public_address(true, DEFAULT_LISTEN_PORT))
                _listen_address = std::move(*maybe_addr);
            else
                throw std::runtime_error{"Could not find net interface on current platform!"};
        }

        _public_address = (not paddr and not pport) ? _listen_address
                                                    : oxen::quic::Address{*paddr, pport ? *pport : DEFAULT_LISTEN_PORT};

        RouterContact::BLOCK_BOGONS = conf.router.block_bogons;

        auto& networkConfig = conf.network;

        /// build a set of  strictConnectPubkeys
        if (not networkConfig.strict_connect.empty())
        {
            const auto& val = networkConfig.strict_connect;

            if (is_service_node())
                throw std::runtime_error("cannot use strict-connect option as service node");

            if (val.size() < 2)
                throw std::runtime_error("Must specify more than one strict-connect router if using strict-connect");

            _node_db->pinned_edges().insert(val.begin(), val.end());
            log::debug(logcat, "{} strict-connect routers configured", val.size());
        }

        _bootstrap_seed = conf.bootstrap.seednode;

        std::vector<fs::path> bootstrap_paths{std::move(conf.bootstrap.files)};

        fs::path default_bootstrap = conf.router.data_dir / "bootstrap.signed";

        auto& bootstrap = _node_db->bootstrap_list();

        bootstrap.populate_bootstraps(bootstrap_paths, default_bootstrap, not _bootstrap_seed);

        // profiling
        _profile_file = conf.router.data_dir / "profiles.dat";

        // Network config
        if (conf.network.enable_profiling.value_or(false))
        {
            LogInfo("router profiling enabled");
            if (not fs::exists(_profile_file))
            {
                LogInfo("no profiles file at ", _profile_file, " skipping");
            }
            else
            {
                LogInfo("loading router profiles from ", _profile_file);
                router_profiling().Load(_profile_file);
            }
        }
        else
        {
            router_profiling().Disable();
            LogInfo("router profiling disabled");
        }

        // API config
        if (not is_service_node())
        {
            hidden_service_context().AddEndpoint(conf);
        }

        return true;
    }

    bool Router::is_bootstrap_node(const RouterID r) const
    {
        return _node_db->has_bootstraps() ? _node_db->bootstrap_list().contains(r) : false;
    }

    bool Router::should_report_stats(llarp_time_t now) const
    {
        return now - _last_stats_report > REPORT_STATS_INTERVAL;
    }

    std::string Router::_stats_line()
    {
        auto [_in, _out, _relay, _client] = _link_manager->connection_stats();
        auto [_rcs, _rids, _bstraps] = _node_db->db_stats();

        return "{} RCs, {} RIDs, {} bstraps, conns [{}:{} in:out, {}:{} relay:client]"_format(
            _rcs, _rids, _bstraps, _in, _out, _relay, _client);
    }

    void Router::report_stats()
    {
        const auto now = llarp::time_now_ms();

        log::critical(logcat, "Local {}: {}", is_service_node() ? "Service Node" : "Client", _stats_line());

        if (is_service_node() and fully_meshed())
        {
            log::critical(logcat, "SERVICE NODE IS FULLY MESHED");
        }

        if (_last_stats_report > 0s)
            log::info(logcat, "Last reported stats time {}", now - _last_stats_report);

        _last_stats_report = now;

        oxen::log::flush();
    }

    std::string Router::status_line()
    {
        auto line = "v{}{}: {}"_format(
            fmt::join(llarp::LOKINET_VERSION, "."), (_is_service_node) ? " snode: " : " client: ", _stats_line());

        if (is_service_node())
        {
            bool have_gossiped = last_rc_gossip == std::chrono::system_clock::time_point::min();
            line += ", gossip [{}:{} next:last]"_format(
                short_time_from_now(next_rc_gossip), have_gossiped ? short_time_from_now(last_rc_gossip) : "never");
        }

        return line;
    }

    void Router::Tick()
    {
        if (is_stopping)
            return;

        const bool is_snode = is_service_node();
        const bool is_decommed = appears_decommed();

        const auto& local = local_rid();

        if (is_snode and not node_db()->registered_routers().count(local))
        {
            log::critical(logcat, "We are NOT registered router, figure it out!");
            // update tick timestamp
            _last_tick = llarp::time_now_ms();
            return;
        }

        const auto now = llarp::time_now_ms();
        auto now_timepoint = std::chrono::system_clock::time_point(now);

        if (const auto delta = now - _last_tick; _last_tick != 0s and delta > NETWORK_RESET_SKIP_INTERVAL)
        {
            // we detected a time skip into the futre, thaw the network
            log::error(logcat, "Timeskip of {} detected, resetting network state!", delta.count());
            Thaw();
        }

        llarp::sys::service_manager->report_periodic_stats();

        _pathbuild_limiter.Decay(now);

        router_profiling().Tick();

        if (should_report_stats(now))
        {
            report_stats();
        }

        // (relay-only) if we have fetched the relay list from oxend and
        // we are registered and funded, we want to gossip our RC periodically
        if (is_snode)
        {
            if (now_timepoint > next_rc_gossip)
            {
                log::critical(logcat, "Regenerating and gossiping RC...");

                router_contact.resign();
                save_rc();

                _link_manager->gossip_rc(local_rid(), router_contact.to_remote());

                last_rc_gossip = now_timepoint;

                // TESTNET: 0 to 3 minutes before testnet gossip interval
                auto delta = std::chrono::seconds{std::uniform_int_distribution<size_t>{0, 180}(llarp::csrng)};

                next_rc_gossip = now_timepoint + TESTNET_GOSSIP_INTERVAL - delta;
            }
        }

        if (needs_rebootstrap() and now_timepoint > next_bootstrap_attempt)
        {
            node_db()->fallback_to_bootstrap();
        }
        else if (needs_initial_fetch() and now_timepoint > next_initial_fetch_attempt)
        {
            if (not _config->bootstrap.seednode)
                node_db()->fetch_initial(is_service_node());
        }
        else if (not is_snode and node_db()->initial_fetch_completed())
        {
            // (client-only) periodically fetch updated RCs
            if (now_timepoint - last_rc_fetch > RC_UPDATE_INTERVAL)
            {
                log::critical(logcat, "Time to fetch RCs!");
                node_db()->fetch_rcs();
            }

            // (client-only) periodically fetch updated RouterID list
            if (now_timepoint - last_rid_fetch > ROUTERID_UPDATE_INTERVAL)
            {
                log::critical(logcat, "Time to fetch RIDs!");
                node_db()->fetch_rids();
            }
        }

        // remove RCs for nodes that are no longer allowed by network policy
        node_db()->remove_if([&](const RemoteRC& rc) -> bool {
            // don't purge bootstrap nodes from nodedb
            if (is_bootstrap_node(rc.router_id()))
            {
                log::trace(logcat, "Not removing {}: is bootstrap node", rc.router_id());
                return false;
            }

            // if for some reason we stored an RC that isn't a valid router
            // purge this entry
            if (not rc.is_public_addressable())
            {
                log::debug(logcat, "Removing {}: not a valid router", rc.router_id());
                return true;
            }

            // clear out a fully expired RC
            if (rc.is_expired(now))
            {
                log::debug(logcat, "Removing {}: RC is expired", rc.router_id());
                return true;
            }

            // clients have no notion of a whilelist
            // we short circuit logic here so we dont remove
            // routers that are not whitelisted for first hops
            if (not is_snode)
            {
                log::trace(logcat, "Not removing {}: we are a client and it looks fine", rc.router_id());
                return false;
            }

            // if we don't have the whitelist yet don't remove the entry
            if (not whitelist_received)
            {
                log::debug(logcat, "Skipping check on {}: don't have whitelist yet", rc.router_id());
                return false;
            }
            // if we have no whitelist enabled or we have
            // the whitelist enabled and we got the whitelist
            // check against the whitelist and remove if it's not
            // in the whitelist OR if there is no whitelist don't remove
            if (not node_db()->is_connection_allowed(rc.router_id()))
            {
                log::debug(logcat, "Removing {}: not a valid router", rc.router_id());
                return true;
            }
            return false;
        });

        _link_manager->check_persisting_conns(now);

        auto num_router_conns = num_router_connections();
        auto num_rcs = node_db()->num_rcs();

        if (is_snode)
        {
            if (now >= _next_decomm_warning)
            {
                if (auto registered = appears_registered(), funded = appears_funded();
                    not(registered and funded and not is_decommed))
                {
                    // complain about being deregistered/decommed/unfunded
                    log::error(
                        logcat,
                        "We are running as a service node but we seem to be {}",
                        not registered    ? "deregistered"
                            : is_decommed ? "decommissioned"
                                          : "not fully staked");
                    _next_decomm_warning = now + DECOMM_WARNING_INTERVAL;
                }
                else if (insufficient_peers())
                {
                    log::error(
                        logcat,
                        "We appear to be an active service node, but have only {} known peers.",
                        node_db()->num_rcs());
                    _next_decomm_warning = now + DECOMM_WARNING_INTERVAL;
                }
            }

            if (num_router_conns < num_rcs)
            {
                log::critical(
                    logcat, "Service Node connecting to {} random routers to achieve full mesh", FULL_MESH_ITERATION);
                _link_manager->connect_to_random(FULL_MESH_ITERATION);
            }
        }
        else
        {
            size_t min_client_conns = MIN_CLIENT_ROUTER_CONNS;
            const auto& pinned_edges = _node_db->pinned_edges();
            const auto pinned_count = pinned_edges.size();

            if (pinned_count > 0 && min_client_conns > pinned_count)
                min_client_conns = pinned_count;

            // if we need more sessions to routers and we are not a service node kicked from the
            // network or we are a client we shall connect out to others
            if (num_router_conns < min_client_conns)
            {
                size_t needed = min_client_conns - num_router_conns;
                log::critical(logcat, "Client connecting to {} random routers to keep alive", needed);
                _link_manager->connect_to_random(needed);
            }
            else
            {
                // log::critical(
                //     logcat, "Client skipping hidden service exit tick or whatever the fuck that
                //     means");
                // _hidden_service_context.Tick(now);
                // _exit_context.Tick(now);
            }
        }

        // save profiles
        if (router_profiling().ShouldSave(now) and _config->network.save_profiles)
        {
            queue_disk_io([&]() { router_profiling().Save(_profile_file); });
        }

        _node_db->Tick(now);

        paths.ExpirePaths(now);

        // update tick timestamp
        _last_tick = llarp::time_now_ms();
    }

    const std::set<RouterID>& Router::get_whitelist() const
    {
        return _node_db->whitelist();
    }

    void Router::set_router_whitelist(
        const std::vector<RouterID>& whitelist,
        const std::vector<RouterID>& greylist,
        const std::vector<RouterID>& unfundedlist)
    {
        node_db()->set_router_whitelist(whitelist, greylist, unfundedlist);
        whitelist_received = true;
    }

    bool Router::StartRpcServer()
    {
        if (_config->api.enable_rpc_server)
            _rpc_server = std::make_unique<rpc::RPCServer>(_lmq, *this);

        return true;
    }

    bool Router::Run()
    {
        log::critical(logcat, "{} called", __PRETTY_FUNCTION__);

        if (is_running || is_stopping)
            return false;

        router_contact =
            LocalRC::make(identity(), _is_service_node and _public_address ? *_public_address : _listen_address);

        _link_manager = LinkManager::make(*this);

        // Init components after relevant config settings loaded
        _link_manager->init();

        if (is_service_node())
        {
            if (not router_contact.is_public_addressable())
            {
                log::error(logcat, "Router is configured as relay but has no reachable addresses!");
                return false;
            }

            save_rc();

            if (not init_service_node())
            {
                log::error(logcat, "Router failed to initialize service node!");
                return false;
            }

            log::info(logcat, "Router initialized as service node!");

            // relays do not use profiling
            router_profiling().Disable();
        }
        else
        {
            // we are a client, regenerate keys and resign rc before everything else
            crypto::identity_keygen(_identity);
            crypto::encryption_keygen(_encryption);
            router_contact.set_router_id(seckey_to_pubkey(identity()));  // resigns RC
        }

        // TESTNET:
        auto our_rid = local_rid().ToString();
        log::critical(logcat, "I am {}", our_rid);

        // if (our_rid == "55fxrybf3jtausbnmxpgwcsz9t8qkf5pr8t5f4xyto4omjrkorpy.snode"sv)
        // {
        //     log::critical(logcat, "I am decaf20: upgrading 'quic' to log::debug and 'bparser' to
        //     log::trace"); oxen::log::set_level("bparser", oxen::log::Level::trace);
        //     oxen::log::set_level("quic", oxen::log::Level::debug);
        // }

        log::info(logcat, "Starting hidden service context...");

        if (!hidden_service_context().StartAll())
        {
            log::error(logcat, "Failed to start hidden service context!");
            return false;
        }

        log::info(logcat, "Loading NodeDB from disk...");
        _node_db->load_from_disk();
        _node_db->store_bootstraps();

        log::info(logcat, "Creating Introset Contacts...");
        _contacts = std::make_unique<Contacts>(*this);

        _loop->call_every(ROUTER_TICK_INTERVAL, weak_from_this(), [this] { Tick(); });

        _route_poker->start();

        is_running.store(true);

        _started_at = now();

        if (is_service_node() and not _testing_disabled)
        {
            // do service node testing if we are in service node whitelist mode
            _loop->call_every(consensus::REACHABILITY_TESTING_TIMER_INTERVAL, weak_from_this(), [this] {
                // dont run tests if we are not running or we are stopping
                if (not is_running)
                    return;
                // dont run tests if we think we should not test other routers
                // this occurs when we are deregistered or do not have the service node list
                // yet when we expect to have one.
                if (not can_test_routers())
                    return;

                auto tests = router_testing.get_failing();

                if (auto maybe = router_testing.next_random(this))
                {
                    tests.emplace_back(*maybe, 0);
                }
                for (const auto& [router, fails] : tests)
                {
                    if (not SessionToRouterAllowed(router))
                    {
                        log::debug(
                            logcat,
                            "{} is no longer a registered service node; dropping from test "
                            "list",
                            router);
                        router_testing.remove_node_from_failing(router);
                        continue;
                    }

                    log::critical(logcat, "Establishing session to {} for service node testing", router);

                    // try to make a session to this random router
                    // this will do a dht lookup if needed
                    _link_manager->test_reachability(
                        router,
                        [this, rid = router, previous = fails](oxen::quic::connection_interface& conn) {
                            log::info(
                                logcat,
                                "Successful SN reachability test to {}{}",
                                rid,
                                previous ? "after {} previous failures"_format(previous) : "");
                            router_testing.remove_node_from_failing(rid);
                            _rpc_client->InformConnection(rid, true);
                            conn.close_connection();
                        },
                        [this, rid = router, previous = fails](oxen::quic::connection_interface&, uint64_t ec) {
                            if (ec != 0)
                            {
                                log::info(
                                    logcat,
                                    "Unsuccessful SN reachability test to {} after {} previous "
                                    "failures",
                                    rid,
                                    previous);
                                router_testing.add_failing_node(rid, previous);
                            }
                        });
                }
            });
        }

        llarp::sys::service_manager->ready();
        return is_running;
    }

    bool Router::IsRunning() const
    {
        return is_running;
    }

    llarp_time_t Router::Uptime() const
    {
        const llarp_time_t _now = now();
        if (_started_at > 0s && _now > _started_at)
            return _now - _started_at;
        return 0s;
    }

    void Router::AfterStopLinks()
    {
        llarp::sys::service_manager->stopping();
        Close();
        log::debug(logcat, "stopping oxenmq");
        _lmq.reset();
    }

    void Router::AfterStopIssued()
    {
        llarp::sys::service_manager->stopping();
        log::debug(logcat, "stopping links");
        StopLinks();
        log::debug(logcat, "saving nodedb to disk");
        node_db()->save_to_disk();
        _loop->call_later(200ms, [this] { AfterStopLinks(); });
    }

    void Router::StopLinks()
    {
        _link_manager->stop();
    }

    void Router::Die()
    {
        if (!is_running)
            return;
        if (is_stopping)
            return;

        is_stopping.store(true);
        if (log::get_level_default() != log::Level::off)
            log::reset_level(log::Level::info);
        LogWarn("stopping router hard");
        llarp::sys::service_manager->stopping();
        hidden_service_context().StopAll();
        _exit_context.stop();
        StopLinks();
        Close();
    }

    void Router::Stop()
    {
        if (!is_running)
        {
            log::debug(logcat, "Stop called, but not running");
            return;
        }
        if (is_stopping)
        {
            log::debug(logcat, "Stop called, but already stopping");
            return;
        }

        is_stopping.store(true);

        if (auto level = log::get_level_default(); level > log::Level::info and level != log::Level::off)
            log::reset_level(log::Level::info);

        log::info(logcat, "stopping service manager...");
        llarp::sys::service_manager->stopping();

        log::debug(logcat, "stopping hidden service context...");
        hidden_service_context().StopAll();

        log::debug(logcat, "stopping exit context...");
        _exit_context.stop();

        _loop->call_later(200ms, [this] { AfterStopIssued(); });
    }

    std::string Router::ShortName() const
    {
        return RouterID(pubkey()).ToString().substr(0, 8);
    }

    uint32_t Router::NextPathBuildNumber()
    {
        return _path_build_count++;
    }

    void Router::ConnectToRandomRouters(int _want)
    {
        const size_t want = _want;
        auto connected = num_router_connections();

        if (connected >= want)
            return;

        _link_manager->connect_to_random(want);
    }

    bool Router::init_service_node()
    {
        log::info(logcat, "Router accepting transit traffic...");
        paths.allow_transit();
        _exit_context.add_exit_endpoint("default", _config->network, _config->dns);
        return true;
    }

    void Router::queue_work(std::function<void(void)> func)
    {
        _lmq->job(std::move(func));
    }

    void Router::queue_disk_io(std::function<void(void)> func)
    {
        _lmq->job(std::move(func), _disk_thread);
    }

    bool Router::HasClientExit() const
    {
        if (is_service_node())
            return false;
        const auto& ep = hidden_service_context().GetDefault();
        return ep and ep->HasExit();
    }

    oxen::quic::Address Router::listen_addr() const
    {
        return _listen_address;
    }

    void Router::init_inbounds()
    {
        // auto addrs = _config->links.InboundListenAddrs;
        // if (is_service_node and addrs.empty())
        // {
        //   LogInfo("Inferring Public Address");

        //   auto maybe_port = _config->links.PublicPort;
        //   if (_config->router.PublicPort and not maybe_port)
        //     maybe_port = _config->router.PublicPort;
        //   if (not maybe_port)
        //     maybe_port = net::port_t::from_host(constants::DefaultInboundIWPPort);

        //   if (auto maybe_addr = net().MaybeInferPublicAddr(*maybe_port))
        //   {
        //     LogInfo("Public Address looks to be ", *maybe_addr);
        //     addrs.emplace_back(std::move(*maybe_addr));
        //   }
        // }
        // if (is_service_node and addrs.empty())
        //   throw std::runtime_error{"we are a service node and we have no inbound links
        //   configured"};

        // // create inbound links, if we are a service node
        // for (auto bind_addr : addrs)
        // {
        //   if (bind_addr.getPort() == 0)
        //     throw std::invalid_argument{"inbound link cannot use port 0"};

        //   if (net().IsWildcardAddress(bind_addr.getIP()))
        //   {
        //     if (auto maybe_ip = public_ip())
        //       bind_addr.setIP(public_ip().host());
        //     else
        //       throw std::runtime_error{"no public ip provided for inbound socket"};
        //   }

        //   AddressInfo ai;
        //   ai.fromSockAddr(bind_addr);

        //   _link_manager.connect_to({ai.IPString(), ai.port}, true);

        //   ai.pubkey = llarp::seckey_topublic(_identity);
        //   ai.dialect = "quicinet";  // FIXME: constant, also better name?
        //   ai.rank = 2;              // FIXME: hardcoded from the beginning...keep?
        //   AddAddressToRC(ai);
        // }
    }

    void Router::init_outbounds()
    {
        // auto addrs = config()->links.OutboundLinks;
        // if (addrs.empty())
        //   addrs.emplace_back(net().Wildcard());

        // for (auto& bind_addr : addrs)
        // {
        //   _link_manager.connect_to({bind_addr.ToString()}, false);
        // }
    }

    const llarp::net::Platform& Router::net() const
    {
        return *llarp::net::Platform::Default_ptr();
    }

}  // namespace llarp
