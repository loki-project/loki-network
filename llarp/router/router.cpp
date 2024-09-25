#include "router.hpp"

#include <llarp/config/config.hpp>
#include <llarp/constants/proto.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dht/node.hpp>
#include <llarp/link/contacts.hpp>
#include <llarp/link/link_manager.hpp>
#include <llarp/link/tunnel.hpp>
#include <llarp/messages/dht.hpp>
#include <llarp/net/net.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/util/formattable.hpp>
#include <llarp/util/logging.hpp>

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

static constexpr std::chrono::milliseconds ROUTER_TICK_INTERVAL{250ms};

namespace llarp
{
    static auto logcat = log::Cat("router");

    std::shared_ptr<Router> Router::make(
        std::shared_ptr<EventLoop> loop, std::shared_ptr<vpn::Platform> vpnPlatform, std::promise<void> p)
    {
        std::shared_ptr<Router> ptr{new Router{std::move(loop), std::move(vpnPlatform), std::move(p)}};
        return ptr;
    }

    Router::Router(std::shared_ptr<EventLoop> loop, std::shared_ptr<vpn::Platform> vpnPlatform, std::promise<void> p)
        : _route_poker{std::make_shared<RoutePoker>(*this)},
          _next_explore_at{std::chrono::steady_clock::now()},
          _lmq{std::make_shared<oxenmq::OxenMQ>()},
          _loop{std::move(loop)},
          _close_promise{std::make_unique<std::promise<void>>(std::move(p))},
          _vpn{std::move(vpnPlatform)},
          _disk_thread{_lmq->add_tagged_thread("disk")},
          _rpc_server{nullptr},
          _last_tick{llarp::time_now_ms()}
    {
        // for lokid, so we don't close the connection when syncing the whitelist
        _lmq->MAX_MSG_SIZE = -1;
    }

    nlohmann::json Router::ExtractStatus() const
    {
        if (not _is_running)
            nlohmann::json{{"running", false}};

        return nlohmann::json{
            {"running", true}, {"numNodesKnown", _node_db->num_rcs()}, {"links", _link_manager->extract_status()}};
    }

    // TODO: investigate changes needed for libquic integration
    nlohmann::json Router::ExtractSummaryStatus() const
    {
        // if (!is_running)
        //   return nlohmann::json{{"running", false}};

        // auto services = _hidden_service_context.ExtractStatus();

        // auto link_types = _link_manager->extract_status();

        // uint64_t tx_rate = 0;
        // uint64_t rx_rate = 0;
        // uint64_t peers = 0;
        // for (const auto& links : link_types)
        // {
        //   for (const auto& link : links)
        //   {
        //     if (link.empty())
        //       continue;
        //     for (const auto& peer : link["sessions"]["established"])
        //     {
        //       tx_rate += peer["tx"].get<uint64_t>();
        //       rx_rate += peer["rx"].get<uint64_t>();
        //       peers++;
        //     }
        //   }
        // }

        // // Compute all stats on all path builders on the default endpoint
        // // Merge snodeSessions, remoteSessions and default into a single array
        // std::vector<nlohmann::json> builders;

        // if (services.is_object())
        // {
        //   const auto& serviceDefault = services.at("default");
        //   builders.push_back(serviceDefault);

        //   auto snode_sessions = serviceDefault.at("snodeSessions");
        //   for (const auto& session : snode_sessions)
        //     builders.push_back(session);

        //   auto remote_sessions = serviceDefault.at("remoteSessions");
        //   for (const auto& session : remote_sessions)
        //     builders.push_back(session);
        // }

        // // Iterate over all items on this array to build the global pathStats
        // uint64_t pathsCount = 0;
        // uint64_t success = 0;
        // uint64_t attempts = 0;
        // for (const auto& builder : builders)
        // {
        //   if (builder.is_null())
        //     continue;

        //   const auto& paths = builder.at("paths");
        //   if (paths.is_array())
        //   {
        //     for (const auto& [key, value] : paths.items())
        //     {
        //       if (value.is_object() && value.at("status").is_string()
        //           && value.at("status") == "established")
        //         pathsCount++;
        //     }
        //   }

        //   const auto& buildStats = builder.at("buildStats");
        //   if (buildStats.is_null())
        //     continue;

        //   success += buildStats.at("success").get<uint64_t>();
        //   attempts += buildStats.at("attempts").get<uint64_t>();
        // }
        // double ratio = static_cast<double>(success) / (attempts + 1);

        nlohmann::json stats{
            {"running", true},
            {"version", llarp::LOKINET_VERSION_FULL},
            {"uptime", to_json(Uptime())},
            // {"numPathsBuilt", pathsCount},
            // {"numPeersConnected", peers},
            {"numRoutersKnown", _node_db->num_rcs()},
            // {"ratio", ratio},
            // {"txRate", tx_rate},
            // {"rxRate", rx_rate},
        };

        // if (services.is_object())
        // {
        //   stats["authCodes"] = services["default"]["authCodes"];
        //   stats["exitMap"] = services["default"]["exitMap"];
        //   stats["networkReady"] = services["default"]["networkReady"];
        //   stats["lokiAddress"] = services["default"]["identity"];
        // }
        return stats;
    }

    void Router::start()
    {
        if (not _loop_ticker)
            throw std::runtime_error{"Router has no main event loop ticker -- Does not exist!"};

        if (not _loop_ticker->is_running())
        {
            if (not _loop_ticker->start())
                throw std::runtime_error{"Router failed to start main event loop ticker!"};

            log::debug(logcat, "Router successfully started main event loop ticker!");
        }
        else
            log::debug(logcat, "Main event loop ticker already auto-started!");

        // TESTNET:
        if (_using_tun)
            _tun->start_poller();

        if (not _systemd_ticker->is_running())
        {
            if (not _systemd_ticker->start())
                throw std::runtime_error{"Failed to start system service report ticker!"};

            log::debug(logcat, "Successfully started system service report ticker");
        }
        else
            log::debug(logcat, "System service report ticker already auto-started!");

        _node_db->start_tickers();

        if (is_service_node())
        {
            _link_manager->start_tickers();

            if (not _testing_disabled)
            {
                if (not _reachability_ticker)
                    throw std::runtime_error{"Router has no service node reachability loop ticker -- Does not exist!"};

                if (not _reachability_ticker->is_running())
                {
                    if (not _reachability_ticker->start())
                        throw std::runtime_error{"Router failed to start service node reachability loop ticker!"};

                    log::debug(logcat, "Router successfully started service node reachability loop ticker!");
                }
                else
                    log::debug(logcat, "Service node reachability loop ticker already auto-started!");
            }
        }
        else
        {
            // Resolve needed ONS values now that we have the necessary things prefigured
            _session_endpoint->resolve_ons_mappings();
        }
    }

    bool Router::fully_meshed() const
    {
        if (auto n_conns = num_router_connections(); n_conns)
            return n_conns >= _node_db->num_rcs();
        return false;
    }

    void Router::persist_connection_until(const RouterID& remote, std::chrono::milliseconds until)
    {
        _link_manager->set_conn_persist(remote, until);
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

    bool Router::ensure_identity()
    {
        log::debug(logcat, "Initializing identity");

        if (is_service_node())
        {
            our_rc_file = _key_manager->rc_path;

#if defined(ANDROID) || defined(IOS)
            log::error(logcat, "running a service node on mobile device is not possible.");
            return false;
#else
#if defined(_WIN32)
            log::error(logcat, "running a service node on windows is not possible.");
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
                    _key_manager->update_idkey(rpc_client()->obtain_identity_key());
                    log::warning(logcat, "Obtained lokid identity key: {}", _key_manager->router_id());

                    rpc_client()->start_pings();
                    break;
                }
                catch (const std::exception& e)
                {
                    log::warning(
                        logcat, "Failed attempt {} of {} to get oxend id keys: ", numTries, maxTries, e.what());

                    if (numTries == maxTries)
                        throw;
                }
            }
        }
        else
        {
            log::debug(logcat, "Client holding identity key generated by key manager...");
        }

        return true;
    }

    void Router::init_logging()
    {
        auto& conf = *_config;

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
        // oxen::log::reset_level(oxen::log::Level::debug);
        oxen::log::set_level("quic", oxen::log::Level::info);
        // oxen::log::set_level("quic", oxen::log::Level::debug);
    }

    void Router::init_rpc()
    {
        if (_is_service_node)
        {
            log::debug(logcat, "Starting RPC client");
            rpc_addr = oxenmq::address(_config->lokid.rpc_addr);
            _rpc_client = std::make_shared<rpc::RPCClient>(_lmq, weak_from_this());
        }

        if (_config->api.enable_rpc_server)
        {
            log::debug(logcat, "Starting RPC server");
            _rpc_server = std::make_unique<rpc::RPCServer>(_lmq, *this);
        }
    }

    void Router::init_bootstrap()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        auto& conf = *_config;

        if (_bootstrap_seed = conf.bootstrap.seednode; _bootstrap_seed)
            log::critical(logcat, "Local instance is bootstrap seed node!");

        std::vector<fs::path> bootstrap_paths{std::move(conf.bootstrap.files)};

        fs::path default_bootstrap = conf.router.data_dir / "bootstrap.signed";

        _node_db->bootstrap_list().populate_bootstraps(
            std::move(bootstrap_paths), default_bootstrap, not _bootstrap_seed);
    }

    void Router::process_routerconfig()
    {
        auto& conf = *_config;

        // Router config
        client_router_connections = conf.router.client_router_connections;

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
            log::critical(logcat, "Using listen address from link config: {}", _listen_address);
        }
        else
        {
            if (paddr or pport)
                throw std::runtime_error{"Must specify [bind]:listen in config with public ip/addr!"};

            log::critical(logcat, "No value in link config listen_addr, querying net-if...");
            if (auto maybe_addr = net().get_best_public_address(true, DEFAULT_LISTEN_PORT))
                _listen_address = std::move(*maybe_addr);
            else
                throw std::runtime_error{"Could not find net interface on current platform!"};
        }

        if (_is_service_node)
        {
            _public_address = (not paddr and not pport)
                ? _listen_address
                : oxen::quic::Address{*paddr, pport ? *pport : DEFAULT_LISTEN_PORT};
        }
        else if (_listen_address.is_addressable())
        {
            log::info(logcat, "Assigning addressible listen address {} as public addr", _listen_address);
            _public_address = _listen_address;
        }
        else
        {
            log::critical(logcat, "Listen address is non-public, querying net-if for public address...");
            auto _port = !_listen_address.is_any_port() and conf.links.only_user_port ? _listen_address.port()
                                                                                      : DEFAULT_LISTEN_PORT;
            if (auto maybe_addr = net().get_best_public_address(true, _port))
                _public_address = std::move(*maybe_addr);
            else
                throw std::runtime_error{"Could not find net interface on current platform!"};
        }

        RouterContact::BLOCK_BOGONS = conf.router.block_bogons;
    }

    void Router::process_netconfig()
    {
        std::string _if_name;
        IPRange _local_range;
        oxen::quic::Address _local_addr;
        ip_v _local_base_ip;
        net::if_info if_info;

        auto& conf = _config->network;

        auto ipv6_enabled = conf.enable_ipv6;

        bool find_if_addr = true;

        // If an ip range is set in the config, then the address and ip optionls are as well
        if (not(conf._local_ip_range and !conf._local_addr->is_any_addr()))
        {
            log::debug(
                logcat,
                "Finding free range for config values (range:{}, addr:{})",
                conf._local_ip_range,
                conf._local_addr);
            const auto maybe = net().find_free_range(ipv6_enabled);

            if (not maybe.has_value())
            {
                throw std::runtime_error("cannot find free address range");
            }

            _local_range = *maybe;
            _local_addr = _local_range.address();
            _local_base_ip = _local_range.base_ip();
        }
        else
        {
            log::debug(
                logcat,
                "Lokinet provided local if-range/addr from config ('{}', {})",
                conf._local_ip_range,
                conf._local_addr);

            find_if_addr = !conf._if_name.has_value();

            _local_range = *conf._local_ip_range;
            _local_addr = *conf._local_addr;
            _local_base_ip = *conf._local_base_ip;
        }

        auto is_v4 = _local_range.is_ipv4();

        log::critical(logcat, "Lokinet has private {} range: {}", is_v4 ? "ipv4" : "ipv6", _local_range);

        if (conf._if_name)
        {
            if_info.if_name = *conf._if_name;

            if (find_if_addr)
            {
                log::debug(logcat, "Finding if address for if-name {}", *if_info.if_name);
                if (auto maybe_addr = net().get_interface_addr(*if_info.if_name, is_v4 ? AF_INET : AF_INET6))
                    if_info.if_addr = *maybe_addr;
                else
                    throw std::runtime_error{"cannot find address for interface name: {}"_format(if_info.if_name)};

                ip_v ipv{};
                if (is_v4)
                    ipv = if_info.if_addr->to_ipv4();
                else
                    ipv = if_info.if_addr->to_ipv6();

                if (auto maybe_index = net().get_interface_index(ipv))
                    if_info.if_index = *maybe_index;
                else
                    throw std::runtime_error{"cannot find index for interface name: {}"_format(*if_info.if_name)};
            }
        }
        else
        {
            if (auto maybe_name = net().find_free_tun(is_v4 ? AF_INET : AF_INET6))
                if_info.if_name = maybe_name;
            else
                throw std::runtime_error("cannot find free interface name");
        }

        conf._if_info = if_info;
        _if_name = *if_info.if_name;

        log::info(logcat, "if-name set to {}", _if_name);

        // set values back in config
        conf._local_ip_range = _local_range;
        conf._local_addr = _local_addr;
        conf._local_base_ip = _local_base_ip;
        conf._if_name = _if_name;

        // process remote client map; addresses must be within _local_ip_range
        auto& client_ips = conf._reserved_local_ips;

        if (not client_ips.empty())
        {
            log::debug(logcat, "Processing remote client map...");

            for (auto itr = client_ips.begin(); itr != client_ips.end();)
            {
                if (conf._local_ip_range->contains(itr->second))
                    itr = client_ips.erase(itr);
                else
                    ++itr;
            }
        }

        /// build a set of strictConnectPubkeys
        if (not conf.strict_connect.empty())
        {
            const auto& val = conf.strict_connect;

            if (is_service_node())
                throw std::runtime_error("cannot use strict-connect option as service node");

            if (val.size() < 2)
                throw std::runtime_error("Must specify more than one strict-connect router if using strict-connect");

            _node_db->pinned_edges().insert(val.begin(), val.end());
            log::debug(logcat, "{} strict-connect routers configured", val.size());
        }

        // profiling
        _profile_file = _config->router.data_dir / "profiles.dat";

        // Network config
        if (not _testnet and _config->network.enable_profiling)
        {
            log::debug(logcat, "Router profiling enabled");
            if (not fs::exists(_profile_file))
            {
                log::debug(logcat, "No profiles file found at {}; skipping...", _profile_file);
            }
            else
            {
                log::debug(logcat, "Loading router profiles from {}", _profile_file);
                _router_profiling.load(_profile_file);
            }
        }
        else
        {
            _router_profiling.disable();
            log::debug(logcat, "Router profiling disabled");
        }
    }

    void Router::init_tun()
    {
        if (_tun = _loop->template make_shared<handlers::TunEndpoint>(*this); _tun != nullptr)
        {
            _tun->configure();
        }
        else
            throw std::runtime_error{"Failed to construct TunEndpoint API!"};
    }

    bool Router::configure(std::shared_ptr<Config> c, std::shared_ptr<NodeDB> nodedb)
    {
        return _loop->call_get([&]() {
            llarp::sys::service_manager->starting();

            _node_db = std::move(nodedb);
            _config = std::move(c);
            auto& conf = *_config;

            init_logging();

            const auto& netid = conf.router.net_id;

            _is_service_node = conf.router.is_relay;
            _is_exit_node = conf.network.allow_exit;

            if (_is_exit_node and _is_service_node)
                throw std::runtime_error{
                    "Lokinet cannot simultaneously operate as a service node and client-operated exit node service!"};

            // Set netid before anything else
            log::debug(logcat, "Network ID set to {}", netid);

            if (not netid.empty() and netid != llarp::LOKINET_DEFAULT_NETID)
            {
                _testnet = netid == llarp::LOKINET_TESTNET_NETID;
                _testing_disabled = conf.lokid.disable_testing;

                RouterContact::ACTIVE_NETID = netid;

                if (_testing_disabled and not _testnet)
                    throw std::runtime_error{"Error: reachability testing can only be disabled on testnet!"};

                log::critical(logcat, "Lokinet network ID is {}, NOT mainnet!", netid);
            }

            log::trace(logcat, "Configuring router...");

            _gossip_interval = TESTNET_GOSSIP_INTERVAL
                + std::chrono::seconds{std::uniform_int_distribution<size_t>{0, 180}(llarp::csrng)};

            log::critical(
                logcat,
                "Local instance operating in {} mode{}",
                _is_service_node ? "relay" : "client",
                _is_exit_node ? " operating an exit node service!" : "!");

            if (conf.router.worker_threads > 0)
                _lmq->set_general_threads(conf.router.worker_threads);

            init_rpc();

            if (_is_service_node)
            {
                log::trace(logcat, "Starting OMQ server");
                _lmq->start();
                log::trace(logcat, "RPC client connecting to RPC bind address");
                _rpc_client->connect_async(rpc_addr);
            }

            log::debug(logcat, "Initializing key manager");

            _key_manager = KeyManager::make(*_config, _is_service_node);

            log::trace(logcat, "Initializing from configuration");

            process_routerconfig();

            log::critical(logcat, "public addr={}, listen addr={}", *_public_address, _listen_address);

            // We process the relevant netconfig values (ip_range, address, and ip) here; in case the range or interface
            // is bad, we search for a free one and set it BACK into the config. Every subsequent object configuring
            // using the NetworkConfig (ex: tun/null, exit::Handler, etc) will have processed values
            process_netconfig();

            init_bootstrap();
            _node_db->configure();

            if (not ensure_identity())
                throw std::runtime_error{"EnsureIdentity() failed"};

            router_contact =
                LocalRC::make(identity(), _is_service_node and _public_address ? *_public_address : _listen_address);

            _path_context = std::make_shared<path::PathContext>(local_rid());

            _session_endpoint = std::make_shared<handlers::SessionEndpoint>(*this);
            _session_endpoint->configure();

            log::debug(logcat, "Creating QUIC link manager...");
            _link_manager = LinkManager::make(*this);

            log::debug(logcat, "Creating QUIC tunnel...");
            _quic_tun = QUICTunnel::make(*this);

            // API config
            //  Full clients have TUN
            //  Embedded clients have nothing
            //  All relays have TUN
            if (_using_tun = conf.network.init_tun; _using_tun)
            {
                log::critical(logcat, "Initializing virtual TUN device...");
                init_tun();
            }

            return true;
        });
    }

    bool Router::is_service_node() const
    {
        return _is_service_node;
    }

    bool Router::is_exit_node() const
    {
        return _is_exit_node;
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

    bool Router::have_snode_whitelist() const
    {
        return whitelist_received;
    }

    bool Router::appears_decommed() const
    {
        return _is_service_node and have_snode_whitelist() and node_db()->greylist().count(local_rid());
    }

    bool Router::appears_funded() const
    {
        return _is_service_node and have_snode_whitelist() and node_db()->is_connection_allowed(local_rid());
    }

    bool Router::appears_registered() const
    {
        return _is_service_node and have_snode_whitelist() and node_db()->registered_routers().count(local_rid());
    }

    bool Router::can_test_routers() const
    {
        return appears_funded() and not _testing_disabled;
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

    bool Router::is_bootstrap_node(const RouterID r) const
    {
        return _node_db->is_bootstrap_node(r);
    }

    bool Router::should_report_stats(std::chrono::milliseconds now) const
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
            line += ", gossip interval={}"_format(_gossip_interval);

        return line;
    }

    void Router::_relay_tick(std::chrono::milliseconds now)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        // auto now_timepoint = std::chrono::system_clock::time_point(now);
        const auto& local = local_rid();

        // TESTNET:
        if (not node_db()->registered_routers().count(local))
        {
            log::trace(logcat, "We are NOT a registered router, figure it out!");
            _last_tick = llarp::time_now_ms();
            return;
        }

        sys::service_manager->report_periodic_stats();

        if (should_report_stats(now))
            report_stats();

        if (not _node_db->tick(now))
        {
            log::trace(logcat, "Router awaiting NodeDB completion to proceed with ::tick() logic...");
            return;
        }

        _link_manager->check_persisting_conns(now);

        const bool is_decommed = appears_decommed();
        auto num_router_conns = num_router_connections();
        auto num_rcs = node_db()->num_rcs();

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

    void Router::_client_tick(std::chrono::milliseconds now)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        llarp::sys::service_manager->report_periodic_stats();
        _pathbuild_limiter.Decay(now);
        // _router_profiling.tick();

        if (should_report_stats(now))
            report_stats();

        if (auto should_proceed = _node_db->tick(now); should_proceed == false)
        {
            log::debug(logcat, "Router awaiting NodeDB completion to proceed with ::tick() logic...");
            return;
        }

        _link_manager->check_persisting_conns(now);

        auto _num_router_conns = num_router_connections();

        const auto& pinned_edges = _node_db->pinned_edges();
        const auto pinned_count = pinned_edges.size();

        auto min_client_conns =
            (pinned_count and MIN_CLIENT_ROUTER_CONNS > pinned_count) ? pinned_count : MIN_CLIENT_ROUTER_CONNS;

        // if we need more sessions to routers we shall connect out to others
        if (_num_router_conns < min_client_conns)
        {
            size_t needed = min_client_conns - _num_router_conns;
            log::critical(
                logcat,
                "Client connecting to {} random routers to keep alive (current:{}, needed:{})",
                needed,
                _num_router_conns,
                min_client_conns);
            _link_manager->connect_to_random(needed);
        }

        _session_endpoint->tick(now);

        // save profiles
        if (_router_profiling.is_enabled() and _config->network.save_profiles and _router_profiling.should_save(now))
            queue_disk_io([&]() { _router_profiling.save(_profile_file); });
    }

    void Router::tick()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_is_stopping)
        {
            log::critical(logcat, "Router is stopping; exiting ::tick()...");
            return;
        }

        const auto now = llarp::time_now_ms();

        if (const auto delta = now - _last_tick; _last_tick != 0s and delta > NETWORK_RESET_SKIP_INTERVAL)
        {
            // we detected a time skip into the futre, thaw the network
            log::error(logcat, "Timeskip of {} detected, resetting network state!", delta.count());
            // TODO: implement a better way to reset the network
            return;
        }

        _is_service_node ? _relay_tick(now) : _client_tick(now);

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

    bool Router::run()
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_is_running || _is_stopping)
            return false;

        if (is_service_node())
        {
            if (not router_contact.is_public_addressable())
            {
                log::error(logcat, "Router is configured as relay but has no reachable addresses!");
                return false;
            }

            save_rc();

            log::info(logcat, "Router accepting transit traffic...");
            _path_context->allow_transit();

            // relays do not use profiling
            _router_profiling.disable();

            log::info(logcat, "Router initialized as service node!");
        }
        else
        {
            // TESTNET:
            _router_profiling.disable();
        }

        // This must be constructed AFTER router creates its LocalRC
        _contacts = std::make_unique<Contacts>(*this);

        log::debug(logcat, "Creating Router::Tick() repeating event...");
        _loop_ticker = _loop->call_every(
            ROUTER_TICK_INTERVAL, [this] { tick(); }, false, true);

        _systemd_ticker = _loop->call_every(
            SERVICE_MANAGER_REPORT_INTERVAL, []() { sys::service_manager->report_periodic_stats(); }, false, true);

        _is_running.store(true);

        _started_at = now();

        if (is_service_node() and not _testing_disabled)
        {
            log::debug(logcat, "Creating reachability testing ticker...");
            // do service node testing if we are in service node whitelist mode
            _reachability_ticker = _loop->call_every(
                consensus::REACHABILITY_TESTING_TIMER_INTERVAL,
                [this] {
                    // dont run tests if we are not running or we are stopping
                    if (not _is_running)
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
                        if (not _node_db->is_connection_allowed(router))
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
                                _rpc_client->inform_connection(rid, true);
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
                },
                false);
        }

        log::critical(logcat, "\n\n\tLOCAL INSTANCE ROUTER ID: {}\n", local_rid());

        llarp::sys::service_manager->ready();
        return _is_running.load();
    }

    bool Router::is_running() const
    {
        return _is_running;
    }

    std::chrono::milliseconds Router::Uptime() const
    {
        const std::chrono::milliseconds _now = now();
        if (_started_at > 0s && _now > _started_at)
            return _now - _started_at;
        return 0s;
    }

    void Router::close()
    {
        log::debug(logcat, "closing");

        if (_router_close_cb)
            _router_close_cb();

        _is_running.store(false);
    }

    void Router::teardown()
    {
        close();
        log::debug(logcat, "stopping oxenmq");
        _lmq.reset();
        _close_promise->set_value();
        _close_promise.reset();
    }

    void Router::cleanup()
    {
        log::debug(logcat, "stopping outbound links");
        stop_outbounds();

        log::debug(logcat, "cleaning up nodedb");
        node_db()->save_to_disk();

        log::debug(logcat, "cleaning up quic_tun...");
        _quic_tun.reset();

        log::debug(logcat, "cleaning up link_manager");
        _link_manager.reset();

        _loop->call_later(200ms, [this] { teardown(); });
    }

    void Router::stop_outbounds()
    {
        _link_manager->close_all_links();

        auto rv = _loop_ticker->stop();
        log::debug(logcat, "router loop ticker stopped {}successfully!", rv ? "" : "un");
        _loop_ticker.reset();

        if (_reachability_ticker)
        {
            log::debug(logcat, "clearing reachability ticker...");
            _reachability_ticker->stop();
            _reachability_ticker.reset();
        }

        log::debug(logcat, "stopping nodedb events");
        node_db()->cleanup();
    }

    void Router::stop_immediately()
    {
        if (!_is_running)
            return;
        if (_is_stopping)
            return;

        _is_stopping.store(true);
        if (log::get_level_default() != log::Level::off)
            log::reset_level(log::Level::info);

        log::warning(logcat, "Hard stopping router");
        llarp::sys::service_manager->stopping();
        _session_endpoint->stop();
        stop_outbounds();
        close();
    }

    void Router::stop()
    {
        if (!_is_running)
        {
            log::debug(logcat, "Stop called, but not running");
            return;
        }
        if (_is_stopping)
        {
            log::debug(logcat, "Stop called, but already stopping");
            return;
        }

        _is_stopping.store(true);

        if (auto level = log::get_level_default(); level > log::Level::info and level != log::Level::off)
            log::reset_level(log::Level::info);

        log::debug(logcat, "stopping service manager...");
        llarp::sys::service_manager->stopping();

        _session_endpoint->stop(true);

        _loop->call_later(200ms, [this] { cleanup(); });
    }

    uint32_t Router::NextPathBuildNumber()
    {
        return _path_build_count++;
    }

    oxen::quic::Address Router::listen_addr() const
    {
        return _listen_address;
    }

    const llarp::net::Platform& Router::net() const
    {
        return *llarp::net::Platform::Default_ptr();
    }

}  // namespace llarp
