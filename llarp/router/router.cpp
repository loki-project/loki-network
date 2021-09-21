#include <memory>
#include "router.hpp"

#include <llarp/config/config.hpp>
#include <llarp/constants/proto.hpp>
#include <llarp/constants/files.hpp>
#include <llarp/crypto/crypto_libsodium.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dht/context.hpp>
#include <llarp/dht/node.hpp>
#include <llarp/iwp/iwp.hpp>
#include <llarp/link/server.hpp>
#include <llarp/messages/link_message.hpp>
#include <llarp/net/net.hpp>
#include <stdexcept>
#include <llarp/util/buffer.hpp>
#include <llarp/util/logging/file_logger.hpp>
#include <llarp/util/logging/json_logger.hpp>
#include <llarp/util/logging/logger_syslog.hpp>
#include <llarp/util/logging/logger.hpp>
#include <llarp/util/meta/memfn.hpp>
#include <llarp/util/str.hpp>
#include <llarp/ev/ev.hpp>
#include <llarp/tooling/peer_stats_event.hpp>

#include <llarp/tooling/router_event.hpp>
#include <llarp/util/status.hpp>

#include <fstream>
#include <cstdlib>
#include <iterator>
#include <unordered_map>
#include <utility>
#if defined(ANDROID) || defined(IOS)
#include <unistd.h>
#endif

#if defined(WITH_SYSTEMD)
#include <systemd/sd-daemon.h>
#endif

#include <oxenmq/oxenmq.h>

static constexpr std::chrono::milliseconds ROUTER_TICK_INTERVAL = 250ms;

namespace llarp
{
  Router::Router(EventLoop_ptr loop, std::shared_ptr<vpn::Platform> vpnPlatform)
      : ready(false)
      , m_lmq(std::make_shared<oxenmq::OxenMQ>())
      , _loop(std::move(loop))
      , _vpnPlatform(std::move(vpnPlatform))
      , paths(this)
      , _exitContext(this)
      , _dht(llarp_dht_context_new(this))
      , m_DiskThread(m_lmq->add_tagged_thread("disk"))
      , inbound_link_msg_parser(this)
      , _hiddenServiceContext(this)
      , m_RPCServer(new rpc::RpcServer(m_lmq, this))
#ifdef LOKINET_HIVE
      , _randomStartDelay(std::chrono::milliseconds((llarp::randint() % 1250) + 2000))
#else
      , _randomStartDelay(std::chrono::seconds((llarp::randint() % 30) + 10))
#endif
  {
    m_keyManager = std::make_shared<KeyManager>();
    // for lokid, so we don't close the connection when syncing the whitelist
    m_lmq->MAX_MSG_SIZE = -1;
    _stopping.store(false);
    _running.store(false);
    _lastTick = llarp::time_now_ms();
    m_NextExploreAt = Clock_t::now();
  }

  Router::~Router()
  {
    llarp_dht_context_free(_dht);
  }

  util::StatusObject
  Router::ExtractStatus() const
  {
    if (_running)
    {
      return util::StatusObject{
          {"running", true},
          {"numNodesKnown", _nodedb->NumLoaded()},
          {"dht", _dht->impl->ExtractStatus()},
          {"services", _hiddenServiceContext.ExtractStatus()},
          {"exit", _exitContext.ExtractStatus()},
          {"links", _linkManager.ExtractStatus()},
          {"outboundMessages", _outboundMessageHandler.ExtractStatus()}};
    }
    else
    {
      return util::StatusObject{{"running", false}};
    }
  }

  util::StatusObject
  Router::ExtractSummaryStatus() const
  {
    if (_running)
    {
      auto services = _hiddenServiceContext.ExtractStatus();
      auto link_types = _linkManager.ExtractStatus();

      int tx_rate = 0;
      int rx_rate = 0;
      int peers = 0;
      for (const auto& links : link_types)
      {
        if (links == nlohmann::json::array())
          continue;
        for (const auto& link : links)
        {
          if (links == nlohmann::json::array())
            continue;
          const auto& established_peers = link["sessions"]["established"];
          for (const auto& peer : established_peers)
          {
            tx_rate += peer["tx"].get<int>();
            rx_rate += peer["rx"].get<int>();
            peers++;
          }
        }
      }

      // Compute all stats on all path builders on the default endpoint
      // Merge snodeSessions, remoteSessions and default into a single array
      std::vector<nlohmann::json> builders;
      auto snode_sessions = services["default"]["snodeSessions"];
      for (const auto& session : snode_sessions)
        builders.push_back(session["buildStats"]);

      auto remote_sessions = services["default"]["remoteSessions"];
      for (const auto& session : remote_sessions)
        builders.push_back(session["buildStats"]);

      builders.push_back(services["default"]["buildStats"]);

      // Iterate over all items on this array to build the global pathStats
      int paths = 0;
      int success = 0;
      int attempts = 0;
      for (const auto& builder : builders)
      {
        if (builder.is_null())
          continue;
        if (builder["length"].is_number())
          paths += builder["length"].get<int>();
        if (builder["success"].is_number())
          success += builder["success"].get<int>();
        if (builder["attempts"].is_number())
          attempts += builder["attempts"].get<int>();
      }
      double ratio = static_cast<double>(success) / (attempts + 1);

      return util::StatusObject{
          {"running", true},
          {"authCodes", services["default"]["authCodes"]},
          {"exitMap", services["default"]["exitMap"]},
          {"lokiAddress", services["default"]["identity"]},
          {"numPathsBuilt", paths},
          {"numPeersConnected", peers},
          {"numRoutersKnown", _nodedb->NumLoaded()},
          {"ratio", ratio},
          {"txRate", tx_rate},
          {"rxRate", rx_rate},
      };
    }
    else
    {
      return util::StatusObject{{"running", false}};
    }
  }

  bool
  Router::HandleRecvLinkMessageBuffer(ILinkSession* session, const llarp_buffer_t& buf)
  {
    if (_stopping)
      return true;

    if (!session)
    {
      LogWarn("no link session");
      return false;
    }
    return inbound_link_msg_parser.ProcessFrom(session, buf);
  }

  void
  Router::Thaw()
  {
    // get pubkeys we are connected to
    std::unordered_set<RouterID> peerPubkeys;
    linkManager().ForEachPeer([&peerPubkeys](auto peer) {
      if (not peer)
        return;
      peerPubkeys.emplace(peer->GetPubKey());
    });
    // close our sessions to them on link layer
    linkManager().ForEachOutboundLink([peerPubkeys](const auto& link) {
      for (const auto& remote : peerPubkeys)
        link->CloseSessionTo(remote);
    });
    // thaw endpoints
    hiddenServiceContext().ForEachService([](const auto& name, const auto& ep) -> bool {
      LogInfo(name, " thawing...");
      ep->Thaw();
      return true;
    });
    LogInfo("We are ready to go bruh...  probably");
  }

  void
  Router::PersistSessionUntil(const RouterID& remote, llarp_time_t until)
  {
    _linkManager.PersistSessionUntil(remote, until);
  }

  void
  Router::GossipRCIfNeeded(const RouterContact rc)
  {
    if (disableGossipingRC_TestingOnly())
      return;

    /// if we are not a service node forget about gossip
    if (not IsServiceNode())
      return;
    /// wait for random uptime
    if (std::chrono::milliseconds{Uptime()} < _randomStartDelay)
      return;
    _rcGossiper.GossipRC(rc);
  }

  bool
  Router::GetRandomGoodRouter(RouterID& router)
  {
    if (whitelistRouters)
    {
      return _rcLookupHandler.GetRandomWhitelistRouter(router);
    }

    if (const auto maybe = nodedb()->GetRandom([](const auto&) -> bool { return true; }))
    {
      router = maybe->pubkey;
      return true;
    }
    return false;
  }

  void
  Router::PumpLL()
  {
    llarp::LogTrace("Router::PumpLL() start");
    if (_stopping.load())
      return;
    paths.PumpDownstream();
    paths.PumpUpstream();
    _outboundMessageHandler.Tick();
    _linkManager.PumpLinks();
    llarp::LogTrace("Router::PumpLL() end");
  }

  bool
  Router::SendToOrQueue(const RouterID& remote, const ILinkMessage& msg, SendStatusHandler handler)
  {
    return _outboundMessageHandler.QueueMessage(remote, msg, handler);
  }

  void
  Router::ForEachPeer(std::function<void(const ILinkSession*, bool)> visit, bool randomize) const
  {
    _linkManager.ForEachPeer(visit, randomize);
  }

  void
  Router::ForEachPeer(std::function<void(ILinkSession*)> visit)
  {
    _linkManager.ForEachPeer(visit);
  }

  void
  Router::try_connect(fs::path rcfile)
  {
    RouterContact remote;
    if (!remote.Read(rcfile.string().c_str()))
    {
      LogError("failure to decode or verify of remote RC");
      return;
    }
    if (remote.Verify(Now()))
    {
      LogDebug("verified signature");
      _outboundSessionMaker.CreateSessionTo(remote, nullptr);
    }
    else
      LogError(rcfile, " contains invalid RC");
  }

  bool
  Router::EnsureIdentity()
  {
    _encryption = m_keyManager->encryptionKey;

    if (whitelistRouters)
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
          _identity = RpcClient()->ObtainIdentityKey();
          LogWarn("Obtained lokid identity keys");
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
      _identity = m_keyManager->identityKey;
    }

    if (_identity.IsZero())
      return false;
    if (_encryption.IsZero())
      return false;

    return true;
  }

  bool
  Router::Configure(std::shared_ptr<Config> c, bool isSNode, std::shared_ptr<NodeDB> nodedb)
  {
    m_Config = std::move(c);
    auto& conf = *m_Config;
    whitelistRouters = conf.lokid.whitelistRouters;
    if (whitelistRouters)
    {
      lokidRPCAddr = oxenmq::address(conf.lokid.lokidRPCAddr);
      m_lokidRpcClient = std::make_shared<rpc::LokidRpcClient>(m_lmq, weak_from_this());
    }

    enableRPCServer = conf.api.m_enableRPCServer;
    if (enableRPCServer)
      rpcBindAddr = oxenmq::address(conf.api.m_rpcBindAddr);

    if (not StartRpcServer())
      throw std::runtime_error("Failed to start rpc server");

    if (conf.router.m_workerThreads > 0)
      m_lmq->set_general_threads(conf.router.m_workerThreads);

    m_lmq->start();

    _nodedb = std::move(nodedb);

    m_isServiceNode = conf.router.m_isRelay;

    if (whitelistRouters)
    {
      m_lokidRpcClient->ConnectAsync(lokidRPCAddr);
    }

    // fetch keys
    if (not m_keyManager->initialize(conf, true, isSNode))
      throw std::runtime_error("KeyManager failed to initialize");
    if (!FromConfig(conf))
      throw std::runtime_error("FromConfig() failed");

    if (!InitOutboundLinks())
      throw std::runtime_error("InitOutboundLinks() failed");

    if (not EnsureIdentity())
      throw std::runtime_error("EnsureIdentity() failed");

    m_RoutePoker.Init(this);
    return true;
  }

  /// called in disk worker thread
  void
  Router::HandleSaveRC() const
  {
    std::string fname = our_rc_file.string();
    _rc.Write(fname.c_str());
  }

  bool
  Router::SaveRC()
  {
    LogDebug("verify RC signature");
    if (!_rc.Verify(Now()))
    {
      Dump<MAX_RC_SIZE>(rc());
      LogError("RC is invalid, not saving");
      return false;
    }
    QueueDiskIO([&]() { HandleSaveRC(); });
    return true;
  }

  bool
  Router::IsServiceNode() const
  {
    return m_isServiceNode;
  }

  void
  Router::Close()
  {
    if (_onDown)
      _onDown();
    LogInfo("closing router");
    _loop->stop();
    _running.store(false);
  }

  bool
  Router::ParseRoutingMessageBuffer(
      const llarp_buffer_t& buf, routing::IMessageHandler* h, const PathID_t& rxid)
  {
    return inbound_routing_msg_parser.ParseMessageBuffer(buf, h, rxid, this);
  }

  bool
  Router::LooksDecommissioned() const
  {
    return IsServiceNode() and whitelistRouters and _rcLookupHandler.HaveReceivedWhitelist()
        and _rcLookupHandler.IsGreylisted(pubkey());
  }

  bool
  Router::SessionToRouterAllowed(const RouterID& router) const
  {
    return _rcLookupHandler.SessionIsAllowed(router);
  }

  bool
  Router::PathToRouterAllowed(const RouterID& router) const
  {
    if (LooksDecommissioned())
    {
      // we are decom'd don't allow any paths outbound at all
      return false;
    }
    return _rcLookupHandler.PathIsAllowed(router);
  }

  size_t
  Router::NumberOfConnectedRouters() const
  {
    return _linkManager.NumberOfConnectedRouters();
  }

  size_t
  Router::NumberOfConnectedClients() const
  {
    return _linkManager.NumberOfConnectedClients();
  }

  bool
  Router::UpdateOurRC(bool rotateKeys)
  {
    SecretKey nextOnionKey;
    RouterContact nextRC = _rc;
    if (rotateKeys)
    {
      CryptoManager::instance()->encryption_keygen(nextOnionKey);
      std::string f = encryption_keyfile.string();
      // TODO: use disk worker
      if (nextOnionKey.SaveToFile(f.c_str()))
      {
        nextRC.enckey = seckey_topublic(nextOnionKey);
        _encryption = nextOnionKey;
      }
    }
    if (!nextRC.Sign(identity()))
      return false;
    if (!nextRC.Verify(time_now_ms(), false))
      return false;
    _rc = std::move(nextRC);
    if (rotateKeys)
    {
      // propagate RC by renegotiating sessions
      ForEachPeer([](ILinkSession* s) {
        if (s->RenegotiateSession())
          LogInfo("renegotiated session");
        else
          LogWarn("failed to renegotiate session");
      });
    }
    if (IsServiceNode())
      return SaveRC();
    else
      return true;
  }

  bool
  Router::FromConfig(const Config& conf)
  {
    // Set netid before anything else
    if (!conf.router.m_netId.empty() && strcmp(conf.router.m_netId.c_str(), llarp::DEFAULT_NETID))
    {
      const auto& netid = conf.router.m_netId;
      llarp::LogWarn(
          "!!!! you have manually set netid to be '",
          netid,
          "' which does not equal '",
          llarp::DEFAULT_NETID,
          "' you will run as a different network, good luck "
          "and don't forget: something something MUH traffic "
          "shape correlation !!!!");
      NetID::DefaultValue() = NetID(reinterpret_cast<const byte_t*>(netid.c_str()));
      // reset netid in our rc
      _rc.netID = llarp::NetID();
    }

    // IWP config
    m_OutboundPort = conf.links.m_OutboundLink.port;
    // Router config
    _rc.SetNick(conf.router.m_nickname);
    _outboundSessionMaker.maxConnectedRouters = conf.router.m_maxConnectedRouters;
    _outboundSessionMaker.minConnectedRouters = conf.router.m_minConnectedRouters;

    encryption_keyfile = m_keyManager->m_encKeyPath;
    our_rc_file = m_keyManager->m_rcPath;
    transport_keyfile = m_keyManager->m_transportKeyPath;
    ident_keyfile = m_keyManager->m_idKeyPath;

    if (not conf.router.m_publicAddress.isEmpty())
      _ourAddress = conf.router.m_publicAddress.createSockAddr();

    RouterContact::BlockBogons = conf.router.m_blockBogons;

    // Lokid Config
    whitelistRouters = conf.lokid.whitelistRouters;
    lokidRPCAddr = oxenmq::address(conf.lokid.lokidRPCAddr);

    m_isServiceNode = conf.router.m_isRelay;

    auto& networkConfig = conf.network;

    /// build a set of  strictConnectPubkeys (
    /// TODO: make this consistent with config -- do we support multiple strict connections
    //        or not?
    std::unordered_set<RouterID> strictConnectPubkeys;
    if (not networkConfig.m_strictConnect.empty())
    {
      const auto& val = networkConfig.m_strictConnect;
      if (IsServiceNode())
        throw std::runtime_error("cannot use strict-connect option as service node");
      strictConnectPubkeys.insert(val.begin(), val.end());
    }

    std::vector<fs::path> configRouters = conf.connect.routers;
    configRouters.insert(
        configRouters.end(), conf.bootstrap.files.begin(), conf.bootstrap.files.end());

    // if our conf had no bootstrap files specified, try the default location of
    // <DATA_DIR>/bootstrap.signed. If this isn't present, leave a useful error message
    if (configRouters.empty() and conf.bootstrap.routers.empty())
    {
      // TODO: use constant
      fs::path defaultBootstrapFile = conf.router.m_dataDir / "bootstrap.signed";
      if (fs::exists(defaultBootstrapFile))
      {
        configRouters.push_back(defaultBootstrapFile);
      }
      else if (not conf.bootstrap.seednode)
      {
        LogError("No bootstrap files specified in config file, and the default");
        LogError("bootstrap file ", defaultBootstrapFile, " does not exist.");
        LogError("Please provide a bootstrap file (e.g. run 'lokinet-bootstrap)'");
        throw std::runtime_error("No bootstrap files available.");
      }
    }

    BootstrapList b_list;
    for (const auto& router : configRouters)
    {
      bool isListFile = false;
      {
        std::ifstream inf(router.c_str(), std::ios::binary);
        if (inf.is_open())
        {
          const char ch = inf.get();
          isListFile = ch == 'l';
        }
      }
      if (isListFile)
      {
        if (not BDecodeReadFile(router, b_list))
        {
          throw std::runtime_error(stringify("failed to read bootstrap list file '", router, "'"));
        }
      }
      else
      {
        RouterContact rc;
        if (not rc.Read(router))
        {
          throw std::runtime_error(
              stringify("failed to decode bootstrap RC, file='", router, "' rc=", rc));
        }
        b_list.insert(rc);
      }
    }

    for (const auto& rc : conf.bootstrap.routers)
    {
      b_list.emplace(rc);
    }

    for (auto& rc : b_list)
    {
      if (not rc.Verify(Now()))
      {
        LogWarn("ignoring invalid RC: ", RouterID(rc.pubkey));
        continue;
      }
      bootstrapRCList.emplace(std::move(rc));
    }

    if (bootstrapRCList.empty() and not conf.bootstrap.seednode)
    {
      throw std::runtime_error{"we have no bootstrap nodes"};
    }

    if (conf.bootstrap.seednode)
    {
      LogInfo("we are a seed node");
    }
    else
      LogInfo("Loaded ", bootstrapRCList.size(), " bootstrap routers");

    // Init components after relevant config settings loaded
    _outboundMessageHandler.Init(&_linkManager, &_rcLookupHandler, _loop);
    _outboundSessionMaker.Init(
        this,
        &_linkManager,
        &_rcLookupHandler,
        &_routerProfiling,
        _loop,
        util::memFn(&AbstractRouter::QueueWork, this));
    _linkManager.Init(&_outboundSessionMaker);
    _rcLookupHandler.Init(
        _dht,
        _nodedb,
        _loop,
        util::memFn(&AbstractRouter::QueueWork, this),
        &_linkManager,
        &_hiddenServiceContext,
        strictConnectPubkeys,
        bootstrapRCList,
        whitelistRouters,
        m_isServiceNode);

    std::vector<LinksConfig::LinkInfo> inboundLinks = conf.links.m_InboundLinks;

    if (inboundLinks.empty() and m_isServiceNode)
    {
      const auto& publicAddr = conf.router.m_publicAddress;
      if (publicAddr.isEmpty() or not publicAddr.hasPort())
      {
        throw std::runtime_error(
            "service node enabled but could not find a public IP to bind to; you need to set the "
            "public-ip= and public-port= options");
      }
      inboundLinks.push_back(LinksConfig::LinkInfo{"0.0.0.0", AF_INET, *publicAddr.getPort()});
    }

    // create inbound links, if we are a service node
    for (const LinksConfig::LinkInfo& serverConfig : inboundLinks)
    {
      auto server = iwp::NewInboundLink(
          m_keyManager,
          loop(),
          util::memFn(&AbstractRouter::rc, this),
          util::memFn(&AbstractRouter::HandleRecvLinkMessageBuffer, this),
          util::memFn(&AbstractRouter::Sign, this),
          nullptr,
          util::memFn(&Router::ConnectionEstablished, this),
          util::memFn(&AbstractRouter::CheckRenegotiateValid, this),
          util::memFn(&Router::ConnectionTimedOut, this),
          util::memFn(&AbstractRouter::SessionClosed, this),
          util::memFn(&AbstractRouter::PumpLL, this),
          util::memFn(&AbstractRouter::QueueWork, this));

      const std::string& key = serverConfig.interface;
      int af = serverConfig.addressFamily;
      uint16_t port = serverConfig.port;
      if (!server->Configure(loop(), key, af, port))
      {
        throw std::runtime_error(stringify("failed to bind inbound link on ", key, " port ", port));
      }
      _linkManager.AddLink(std::move(server), true);
    }

    // profiling
    _profilesFile = conf.router.m_dataDir / "profiles.dat";

    // Network config
    if (conf.network.m_enableProfiling.value_or(false))
    {
      LogInfo("router profiling enabled");
      if (not fs::exists(_profilesFile))
      {
        LogInfo("no profiles file at ", _profilesFile, " skipping");
      }
      else
      {
        LogInfo("loading router profiles from ", _profilesFile);
        routerProfiling().Load(_profilesFile);
      }
    }
    else
    {
      routerProfiling().Disable();
      LogInfo("router profiling disabled");
    }

    // API config
    if (not IsServiceNode())
    {
      hiddenServiceContext().AddEndpoint(conf);
    }

    // Logging config
    LogContext::Instance().Initialize(
        conf.logging.m_logLevel,
        conf.logging.m_logType,
        conf.logging.m_logFile,
        conf.router.m_nickname,
        util::memFn(&AbstractRouter::QueueDiskIO, this));

    return true;
  }

  bool
  Router::CheckRenegotiateValid(RouterContact newrc, RouterContact oldrc)
  {
    return _rcLookupHandler.CheckRenegotiateValid(newrc, oldrc);
  }

  bool
  Router::IsBootstrapNode(const RouterID r) const
  {
    return std::count_if(
               bootstrapRCList.begin(),
               bootstrapRCList.end(),
               [r](const RouterContact& rc) -> bool { return rc.pubkey == r; })
        > 0;
  }

  bool
  Router::ShouldReportStats(llarp_time_t now) const
  {
    static constexpr auto ReportStatsInterval = 1h;
    return now - m_LastStatsReport > ReportStatsInterval;
  }

  void
  Router::ReportStats()
  {
    const auto now = Now();
    LogInfo(nodedb()->NumLoaded(), " RCs loaded");
    LogInfo(bootstrapRCList.size(), " bootstrap peers");
    LogInfo(NumberOfConnectedRouters(), " router connections");
    if (IsServiceNode())
    {
      LogInfo(NumberOfConnectedClients(), " client connections");
      LogInfo(_rc.Age(now), " since we last updated our RC");
      LogInfo(_rc.TimeUntilExpires(now), " until our RC expires");
    }
    if (m_LastStatsReport > 0s)
      LogInfo(now - m_LastStatsReport, " last reported stats");
    m_LastStatsReport = now;
  }

  void
  Router::Tick()
  {
    if (_stopping)
      return;
    // LogDebug("tick router");
    const auto now = Now();

#if defined(WITH_SYSTEMD)
    {
      std::stringstream ss;
      ss << "WATCHDOG=1\nSTATUS=v" << llarp::VERSION_STR;
      if (IsServiceNode())
      {
        ss << " snode | known/svc/clients: " << nodedb()->NumLoaded() << "/"
           << NumberOfConnectedRouters() << "/" << NumberOfConnectedClients() << " | "
           << pathContext().CurrentTransitPaths() << " active paths | "
           << "block " << (m_lokidRpcClient ? m_lokidRpcClient->BlockHeight() : 0);
      }
      else
      {
        ss << " client | known/connected: " << nodedb()->NumLoaded() << "/"
           << NumberOfConnectedRouters() << " | path success: ";
        hiddenServiceContext().ForEachService([&ss](const auto& name, const auto& ep) {
          ss << " [" << name << " " << std::setprecision(4)
             << (100.0 * ep->CurrentBuildStats().SuccessRatio()) << "%]";
          return true;
        });
      }
      const auto status = ss.str();
      ::sd_notify(0, status.c_str());
    }
#endif

    m_PathBuildLimiter.Decay(now);

    routerProfiling().Tick();

    if (ShouldReportStats(now))
    {
      ReportStats();
    }

    _rcGossiper.Decay(now);

    _rcLookupHandler.PeriodicUpdate(now);

    const bool gotWhitelist = _rcLookupHandler.HaveReceivedWhitelist();
    const bool isSvcNode = IsServiceNode();
    const bool decom = LooksDecommissioned();

    if (_rc.ExpiresSoon(now, std::chrono::milliseconds(randint() % 10000))
        || (now - _rc.last_updated) > rcRegenInterval)
    {
      LogInfo("regenerating RC");
      if (!UpdateOurRC(false))
        LogError("Failed to update our RC");
    }
    else if (whitelistRouters and gotWhitelist and _rcLookupHandler.SessionIsAllowed(pubkey()))
    {
      // if we have the whitelist enabled, we have fetched the list and we are in either
      // the white or grey list, we want to gossip our RC
      GossipRCIfNeeded(_rc);
    }
    // remove RCs for nodes that are no longer allowed by network policy
    nodedb()->RemoveIf([&](const RouterContact& rc) -> bool {
      // don't purge bootstrap nodes from nodedb
      if (IsBootstrapNode(rc.pubkey))
        return false;
      // if for some reason we stored an RC that isn't a valid router
      // purge this entry
      if (not rc.IsPublicRouter())
        return true;
      // clients have a notion of a whilelist
      // we short circuit logic here so we dont remove
      // routers that are not whitelisted for first hops
      if (not isSvcNode)
        return false;
      // if we have a whitelist enabled and we don't
      // have the whitelist yet don't remove the entry
      if (whitelistRouters and not gotWhitelist)
        return false;
      // if we have no whitelist enabled or we have
      // the whitelist enabled and we got the whitelist
      // check against the whitelist and remove if it's not
      // in the whitelist OR if there is no whitelist don't remove
      return not _rcLookupHandler.SessionIsAllowed(rc.pubkey);
    });

    // find all deregistered relays
    std::unordered_set<PubKey> closePeers;

    _linkManager.ForEachPeer([&](auto session) {
      if (whitelistRouters and not gotWhitelist)
        return;
      if (not session)
        return;
      const auto pk = session->GetPubKey();
      if (session->IsRelay() and not _rcLookupHandler.SessionIsAllowed(pk))
      {
        closePeers.emplace(pk);
      }
    });

    // mark peers as de-registered
    for (auto& peer : closePeers)
      _linkManager.DeregisterPeer(std::move(peer));

    _linkManager.CheckPersistingSessions(now);

    if (not isSvcNode)
    {
      if (HasClientExit())
      {
        m_RoutePoker.Enable();
      }
      else
      {
        m_RoutePoker.Disable();
      }
      m_RoutePoker.Update();
    }

    size_t connected = NumberOfConnectedRouters();
    if (not isSvcNode)
    {
      connected += _linkManager.NumberOfPendingConnections();
    }

    const int interval = isSvcNode ? 5 : 2;
    const auto timepoint_now = Clock_t::now();
    if (timepoint_now >= m_NextExploreAt and not decom)
    {
      _rcLookupHandler.ExploreNetwork();
      m_NextExploreAt = timepoint_now + std::chrono::seconds(interval);
    }
    size_t connectToNum = _outboundSessionMaker.minConnectedRouters;
    const auto strictConnect = _rcLookupHandler.NumberOfStrictConnectRouters();
    if (strictConnect > 0 && connectToNum > strictConnect)
    {
      connectToNum = strictConnect;
    }

    if (decom)
    {
      // complain about being deregistered
      if (now >= m_NextDecommissionWarn)
      {
        constexpr auto DecommissionWarnInterval = 30s;
        LogError("We are running as a service node but we seem to be decommissioned");
        m_NextDecommissionWarn = now + DecommissionWarnInterval;
      }
    }
    else if (connected < connectToNum)
    {
      size_t dlt = connectToNum - connected;
      LogDebug("connecting to ", dlt, " random routers to keep alive");
      _outboundSessionMaker.ConnectToRandomRouters(dlt);
    }

    _hiddenServiceContext.Tick(now);
    _exitContext.Tick(now);

    // save profiles
    if (routerProfiling().ShouldSave(now) and m_Config->network.m_saveProfiles)
    {
      QueueDiskIO([&]() { routerProfiling().Save(_profilesFile); });
    }

    _nodedb->Tick(now);

    if (m_peerDb)
    {
      // TODO: throttle this?
      // TODO: need to capture session stats when session terminates / is removed from link manager
      _linkManager.updatePeerDb(m_peerDb);

      if (m_peerDb->shouldFlush(now))
      {
        LogDebug("Queing database flush...");
        QueueDiskIO([this]() {
          try
          {
            m_peerDb->flushDatabase();
          }
          catch (std::exception& ex)
          {
            LogError("Could not flush peer stats database: ", ex.what());
          }
        });
      }
    }

    // get connected peers
    std::set<dht::Key_t> peersWeHave;
    _linkManager.ForEachPeer([&peersWeHave](ILinkSession* s) {
      if (!s->IsEstablished())
        return;
      peersWeHave.emplace(s->GetPubKey());
    });
    // remove any nodes we don't have connections to
    _dht->impl->Nodes()->RemoveIf(
        [&peersWeHave](const dht::Key_t& k) -> bool { return peersWeHave.count(k) == 0; });
    // expire paths
    paths.ExpirePaths(now);
    // update tick timestamp
    _lastTick = llarp::time_now_ms();
  }

  bool
  Router::Sign(Signature& sig, const llarp_buffer_t& buf) const
  {
    return CryptoManager::instance()->sign(sig, identity(), buf);
  }

  void
  Router::SessionClosed(RouterID remote)
  {
    dht::Key_t k(remote);
    dht()->impl->Nodes()->DelNode(k);

    LogInfo("Session to ", remote, " fully closed");
    if (IsServiceNode())
      return;
    if (const auto maybe = nodedb()->Get(remote); maybe.has_value())
    {
      for (const auto& addr : maybe->addrs)
        m_RoutePoker.DelRoute(addr.toIpAddress().toIP());
    }
  }

  void
  Router::ConnectionTimedOut(ILinkSession* session)
  {
    if (m_peerDb)
    {
      RouterID id{session->GetPubKey()};
      // TODO: make sure this is a public router (on whitelist)?
      m_peerDb->modifyPeerStats(id, [&](PeerStats& stats) { stats.numConnectionTimeouts++; });
    }
    _outboundSessionMaker.OnConnectTimeout(session);
  }

  void
  Router::ModifyOurRC(std::function<std::optional<RouterContact>(RouterContact)> modify)
  {
    if (auto maybe = modify(rc()))
    {
      _rc = *maybe;
      UpdateOurRC();
      _rcGossiper.GossipRC(rc());
    }
  }

  bool
  Router::ConnectionEstablished(ILinkSession* session, bool inbound)
  {
    RouterID id{session->GetPubKey()};
    if (m_peerDb)
    {
      // TODO: make sure this is a public router (on whitelist)?
      m_peerDb->modifyPeerStats(id, [&](PeerStats& stats) { stats.numConnectionSuccesses++; });
    }
    NotifyRouterEvent<tooling::LinkSessionEstablishedEvent>(pubkey(), id, inbound);
    return _outboundSessionMaker.OnSessionEstablished(session);
  }

  bool
  Router::GetRandomConnectedRouter(RouterContact& result) const
  {
    return _linkManager.GetRandomConnectedRouter(result);
  }

  void
  Router::HandleDHTLookupForExplore(RouterID /*remote*/, const std::vector<RouterContact>& results)
  {
    for (const auto& rc : results)
    {
      _rcLookupHandler.CheckRC(rc);
    }
  }

  // TODO: refactor callers and remove this function
  void
  Router::LookupRouter(RouterID remote, RouterLookupHandler resultHandler)
  {
    _rcLookupHandler.GetRC(
        remote,
        [=](const RouterID& id, const RouterContact* const rc, const RCRequestResult result) {
          (void)id;
          if (resultHandler)
          {
            std::vector<RouterContact> routers;
            if (result == RCRequestResult::Success && rc != nullptr)
            {
              routers.push_back(*rc);
            }
            resultHandler(routers);
          }
        });
  }

  void
  Router::SetRouterWhitelist(
      const std::vector<RouterID>& whitelist, const std::vector<RouterID>& greylist)
  {
    _rcLookupHandler.SetRouterWhitelist(whitelist, greylist);
  }

  bool
  Router::StartRpcServer()
  {
    if (enableRPCServer)
    {
      m_RPCServer->AsyncServeRPC(rpcBindAddr);
      LogInfo("Bound RPC server to ", rpcBindAddr);
    }

    return true;
  }

  bool
  Router::Run()
  {
    if (_running || _stopping)
      return false;

    // set public signing key
    _rc.pubkey = seckey_topublic(identity());
    // set router version if service node
    if (IsServiceNode())
    {
      _rc.routerVersion = RouterVersion(llarp::VERSION, LLARP_PROTO_VERSION);
    }

    _linkManager.ForEachInboundLink([&](LinkLayer_ptr link) {
      AddressInfo ai;
      if (link->GetOurAddressInfo(ai))
      {
        // override ip and port
        if (_ourAddress)
        {
          ai.fromSockAddr(*_ourAddress);
        }
        if (RouterContact::BlockBogons && IsBogon(ai.ip))
          return;
        LogInfo("adding address: ", ai);
        _rc.addrs.push_back(ai);
      }
    });

    if (ExitEnabled() and IsServiceNode())
    {
      LogError("exit mode not supported while service node");
      return false;
    }

    if (IsServiceNode() and not _rc.IsPublicRouter())
    {
      LogError("we are configured as relay but have no reachable addresses");
      return false;
    }

    // set public encryption key
    _rc.enckey = seckey_topublic(encryption());

    LogInfo("Signing rc...");
    if (!_rc.Sign(identity()))
    {
      LogError("failed to sign rc");
      return false;
    }

    if (IsServiceNode())
    {
      if (!SaveRC())
      {
        LogError("failed to save RC");
        return false;
      }
    }
    _outboundSessionMaker.SetOurRouter(pubkey());
    if (!_linkManager.StartLinks())
    {
      LogWarn("One or more links failed to start.");
      return false;
    }

    if (IsServiceNode())
    {
      // initialize as service node
      if (!InitServiceNode())
      {
        LogError("Failed to initialize service node");
        return false;
      }
      const RouterID us = pubkey();
      LogInfo("initalized service node: ", us);
      // init gossiper here
      _rcGossiper.Init(&_linkManager, us, this);
      // relays do not use profiling
      routerProfiling().Disable();
    }
    else
    {
      // we are a client
      // regenerate keys and resign rc before everything else
      CryptoManager::instance()->identity_keygen(_identity);
      CryptoManager::instance()->encryption_keygen(_encryption);
      _rc.pubkey = seckey_topublic(identity());
      _rc.enckey = seckey_topublic(encryption());
      if (!_rc.Sign(identity()))
      {
        LogError("failed to regenerate keys and sign RC");
        return false;
      }
    }

    LogInfo("starting hidden service context...");
    if (!hiddenServiceContext().StartAll())
    {
      LogError("Failed to start hidden service context");
      return false;
    }

    {
      LogInfo("Loading nodedb from disk...");
      _nodedb->LoadFromDisk();
    }

    llarp_dht_context_start(dht(), pubkey());

    for (const auto& rc : bootstrapRCList)
    {
      nodedb()->Put(rc);
      _dht->impl->Nodes()->PutNode(rc);
      LogInfo("added bootstrap node ", RouterID{rc.pubkey});
    }

    LogInfo("have ", _nodedb->NumLoaded(), " routers");

#ifdef _WIN32
    // windows uses proactor event loop so we need to constantly pump
    _loop->add_ticker([this] { PumpLL(); });
#else
    _loop->set_pump_function([this] { PumpLL(); });
#endif
    _loop->call_every(ROUTER_TICK_INTERVAL, weak_from_this(), [this] { Tick(); });
    _running.store(true);
    _startedAt = Now();
#if defined(WITH_SYSTEMD)
    ::sd_notify(0, "READY=1");
#endif
    if (whitelistRouters)
    {
      // do service node testing if we are in service node whitelist mode
      _loop->call_every(consensus::REACHABILITY_TESTING_TIMER_INTERVAL, weak_from_this(), [this] {
        // dont run tests if we are not running or we are stopping
        if (not _running)
          return;
        // dont run tests if we are decommissioned
        if (LooksDecommissioned())
          return;
        auto tests = m_routerTesting.get_failing();
        if (auto maybe = m_routerTesting.next_random(this))
        {
          tests.emplace_back(*maybe, 0);
        }
        for (const auto& [router, fails] : tests)
        {
          if (not SessionToRouterAllowed(router))
          {
            LogDebug(
                router,
                " is no longer a registered service node so we remove it from the testing list");
            m_routerTesting.remove_node_from_failing(router);
            continue;
          }
          LogDebug("Establishing session to ", router, " for SN testing");
          // try to make a session to this random router
          // this will do a dht lookup if needed
          _outboundSessionMaker.CreateSessionTo(
              router, [previous_fails = fails, this](const auto& router, const auto result) {
                auto rpc = RpcClient();

                if (result != SessionResult::Establish)
                {
                  // failed connection mark it as so
                  m_routerTesting.add_failing_node(router, previous_fails);
                  LogInfo(
                      "FAILED SN connection test to ",
                      router,
                      " (",
                      previous_fails + 1,
                      " consecutive failures) result=",
                      result);
                }
                else
                {
                  m_routerTesting.remove_node_from_failing(router);
                  if (previous_fails > 0)
                  {
                    LogInfo(
                        "Successful SN connection test to ",
                        router,
                        " after ",
                        previous_fails,
                        " failures");
                  }
                  else
                  {
                    LogDebug("Successful SN connection test to ", router);
                  }
                }
                if (rpc)
                {
                  // inform as needed
                  rpc->InformConnection(router, result == SessionResult::Establish);
                }
              });
        }
      });
    }
    LogContext::Instance().DropToRuntimeLevel();
    return _running;
  }

  bool
  Router::IsRunning() const
  {
    return _running;
  }

  llarp_time_t
  Router::Uptime() const
  {
    const llarp_time_t _now = Now();
    if (_startedAt > 0s && _now > _startedAt)
      return _now - _startedAt;
    return 0s;
  }

  void
  Router::AfterStopLinks()
  {
    Close();
    m_lmq.reset();
  }

  void
  Router::AfterStopIssued()
  {
    StopLinks();
    nodedb()->SaveToDisk();
    _loop->call_later(200ms, [this] { AfterStopLinks(); });
  }

  void
  Router::StopLinks()
  {
    _linkManager.Stop();
  }

  void
  Router::Die()
  {
    if (!_running)
      return;
    if (_stopping)
      return;

    _stopping.store(true);
    LogContext::Instance().RevertRuntimeLevel();
    LogWarn("stopping router hard");
#if defined(WITH_SYSTEMD)
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down HARD");
#endif
    hiddenServiceContext().StopAll();
    _exitContext.Stop();
    StopLinks();
    Close();
  }

  void
  Router::Stop()
  {
    if (!_running)
      return;
    if (_stopping)
      return;

    _stopping.store(true);
    LogContext::Instance().RevertRuntimeLevel();
    LogInfo("stopping router");
#if defined(WITH_SYSTEMD)
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");
#endif
    hiddenServiceContext().StopAll();
    _exitContext.Stop();
    paths.PumpUpstream();
    _linkManager.PumpLinks();
    _loop->call_later(200ms, [this] { AfterStopIssued(); });
  }

  bool
  Router::HasSessionTo(const RouterID& remote) const
  {
    return _linkManager.HasSessionTo(remote);
  }

  std::string
  Router::ShortName() const
  {
    return RouterID(pubkey()).ToString().substr(0, 8);
  }

  uint32_t
  Router::NextPathBuildNumber()
  {
    return path_build_count++;
  }

  void
  Router::ConnectToRandomRouters(int _want)
  {
    const size_t want = _want;
    auto connected = NumberOfConnectedRouters();
    if (not IsServiceNode())
    {
      connected += _linkManager.NumberOfPendingConnections();
    }
    if (connected >= want)
      return;
    _outboundSessionMaker.ConnectToRandomRouters(want);
  }

  bool
  Router::InitServiceNode()
  {
    LogInfo("accepting transit traffic");
    paths.AllowTransit();
    llarp_dht_allow_transit(dht());
    _exitContext.AddExitEndpoint("default", m_Config->network, m_Config->dns);
    return true;
  }

  bool
  Router::TryConnectAsync(RouterContact rc, uint16_t tries)
  {
    (void)tries;

    if (rc.pubkey == pubkey())
    {
      return false;
    }

    if (not _rcLookupHandler.SessionIsAllowed(rc.pubkey))
    {
      return false;
    }

    _outboundSessionMaker.CreateSessionTo(rc, nullptr);

    return true;
  }

  void
  Router::QueueWork(std::function<void(void)> func)
  {
    if (m_isServiceNode)
      _loop->call_soon(std::move(func));
    else
      m_lmq->job(std::move(func));
  }

  void
  Router::QueueDiskIO(std::function<void(void)> func)
  {
    m_lmq->job(std::move(func), m_DiskThread);
  }

  bool
  Router::HasClientExit() const
  {
    if (IsServiceNode())
      return false;
    const auto ep = hiddenServiceContext().GetDefault();
    return ep and ep->HasExit();
  }

  bool
  Router::InitOutboundLinks()
  {
    auto link = iwp::NewOutboundLink(
        m_keyManager,
        loop(),
        util::memFn(&AbstractRouter::rc, this),
        util::memFn(&AbstractRouter::HandleRecvLinkMessageBuffer, this),
        util::memFn(&AbstractRouter::Sign, this),
        [&](llarp::RouterContact rc) {
          if (IsServiceNode())
            return;
          llarp::LogTrace(
              "Before connect, outbound link adding route to (",
              rc.addrs[0].toIpAddress().toIP(),
              ") via gateway.");
          m_RoutePoker.AddRoute(rc.addrs[0].toIpAddress().toIP());
        },
        util::memFn(&Router::ConnectionEstablished, this),
        util::memFn(&AbstractRouter::CheckRenegotiateValid, this),
        util::memFn(&Router::ConnectionTimedOut, this),
        util::memFn(&AbstractRouter::SessionClosed, this),
        util::memFn(&AbstractRouter::PumpLL, this),
        util::memFn(&AbstractRouter::QueueWork, this));

    if (!link)
      throw std::runtime_error("NewOutboundLink() failed to provide a link");

    for (const auto af : {AF_INET, AF_INET6})
    {
      if (not link->Configure(loop(), "*", af, m_OutboundPort))
        continue;

#if defined(ANDROID)
      m_OutboundUDPSocket = link->GetUDPFD().value_or(-1);
#endif
      _linkManager.AddLink(std::move(link), false);
      return true;
    }
    throw std::runtime_error(
        stringify("Failed to init AF_INET and AF_INET6 on port ", m_OutboundPort));
  }

  void
  Router::MessageSent(const RouterID& remote, SendStatus status)
  {
    if (status == SendStatus::Success)
    {
      LogDebug("Message successfully sent to ", remote);
    }
    else
    {
      LogDebug("Message failed sending to ", remote);
    }
  }

  void
  Router::HandleRouterEvent(tooling::RouterEventPtr event) const
  {
    LogDebug(event->ToString());
  }

}  // namespace llarp
