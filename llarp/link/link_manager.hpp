#pragma once

#include "connection.hpp"
#include <llarp/constants/path.hpp>
#include <llarp/util/decaying_hashset.hpp>

#include <llarp/router/rc_lookup_handler.hpp>
#include <llarp/router_contact.hpp>
#include <llarp/peerstats/peer_db.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/util/compare_ptr.hpp>

#include <quic.hpp>

#include <unordered_map>
#include <set>
#include <atomic>

#include <llarp/util/logging.hpp>
#include <llarp/util/priority_queue.hpp>

namespace
{
  static auto quic_cat = llarp::log::Cat("lokinet.quic");
}  // namespace

namespace llarp
{
  struct LinkManager;

  namespace link
  {
    struct Connection;

    struct Endpoint
    {
      Endpoint(std::shared_ptr<oxen::quic::Endpoint> ep, LinkManager& lm)
          : endpoint{std::move(ep)}, link_manager{lm}
      {}

      std::shared_ptr<oxen::quic::Endpoint> endpoint;
      LinkManager& link_manager;

      // for outgoing packets, we route via RouterID; map RouterID->Connection
      // for incoming packets, we get a ConnectionID; map ConnectionID->RouterID
      std::unordered_map<RouterID, std::shared_ptr<link::Connection>> conns;
      std::unordered_map<oxen::quic::ConnectionID, RouterID> connid_map;

      // TODO: see which of these is actually useful and delete the other
      std::shared_ptr<link::Connection>
      get_conn(const RouterContact&) const;
      std::shared_ptr<link::Connection>
      get_conn(const RouterID&) const;

      bool
      have_conn(const RouterID& remote, bool client_only) const;

      bool
      deregister_peer(RouterID remote);

      size_t
      num_connected(bool clients_only) const;

      bool
      get_random_connection(RouterContact& router) const;

      template <typename... Opt>
      bool
      establish_connection(
          const oxen::quic::Address& remote, const RouterContact& rc, Opt&&... opts);

      void
      for_each_connection(std::function<void(link::Connection&)> func);

      void
      close_connection(RouterID rid);

     private:
    };
  }  // namespace link

  enum class SessionResult
  {
    Establish,
    Timeout,
    RouterNotFound,
    InvalidRouter,
    NoLink,
    EstablishFail
  };

  constexpr std::string_view
  ToString(SessionResult sr)
  {
    return sr == llarp::SessionResult::Establish     ? "success"sv
        : sr == llarp::SessionResult::Timeout        ? "timeout"sv
        : sr == llarp::SessionResult::NoLink         ? "no link"sv
        : sr == llarp::SessionResult::InvalidRouter  ? "invalid router"sv
        : sr == llarp::SessionResult::RouterNotFound ? "not found"sv
        : sr == llarp::SessionResult::EstablishFail  ? "establish failed"sv
                                                     : "???"sv;
  }
  template <>
  constexpr inline bool IsToStringFormattable<SessionResult> = true;

  struct PendingMessage
  {
    std::string body;
    RouterID rid;
    bool is_control{false};

    PendingMessage(std::string b, bool control = false) : body{std::move(b)}, is_control{control}
    {}
  };

  struct PendingDataMessage : PendingMessage
  {
    PendingDataMessage(std::string b) : PendingMessage(b)
    {}
  };

  struct PendingControlMessage : PendingMessage
  {
    std::string endpoint;
    std::function<void(oxen::quic::message)> func;

    PendingControlMessage(
        std::string b, std::string e, std::function<void(oxen::quic::message)> f = nullptr)
        : PendingMessage(b, true), endpoint{std::move(e)}, func{std::move(f)}
    {}
  };

  using MessageQueue = std::deque<PendingMessage>;

  struct Router;

  struct LinkManager
  {
   public:
    explicit LinkManager(Router& r);

    bool
    send_control_message(
        const RouterID& remote,
        std::string endpoint,
        std::string body,
        std::function<void(oxen::quic::message)> = nullptr);

    bool
    send_data_message(const RouterID& remote, std::string data);

    Router&
    router() const
    {
      return _router;
    }

   private:
    bool
    send_control_message_impl(
        const RouterID& remote,
        std::string endpoint,
        std::string body,
        std::function<void(oxen::quic::message)> = nullptr);

    friend struct link::Endpoint;

    std::atomic<bool> is_stopping;
    // DISCUSS: is this necessary? can we reduce the amount of locking and nuke this
    mutable util::Mutex m;  // protects persisting_conns

    // sessions to persist -> timestamp to end persist at
    std::unordered_map<RouterID, llarp_time_t> persisting_conns GUARDED_BY(_mutex);

    // holds any messages we attempt to send while connections are establishing
    std::unordered_map<RouterID, MessageQueue> pending_conn_msg_queue;

    util::DecayingHashSet<RouterID> clients{path::DEFAULT_LIFETIME};

    RCLookupHandler* rc_lookup;
    std::shared_ptr<NodeDB> node_db;

    oxen::quic::Address addr;

    Router& _router;

    // FIXME: Lokinet currently expects to be able to kill all network functionality before
    // finishing other shutdown things, including destroying this class, and that is all in
    // Network's destructor, so we need to be able to destroy it before this class.
    std::unique_ptr<oxen::quic::Network> quic;
    std::shared_ptr<oxen::quic::GNUTLSCreds> tls_creds;
    link::Endpoint ep;

    void
    recv_data_message(oxen::quic::dgram_interface& dgi, bstring dgram);

    void
    recv_control_message(oxen::quic::message msg);

    void
    on_conn_open(oxen::quic::connection_interface& ci);

    void
    on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec);

    std::shared_ptr<oxen::quic::Endpoint>
    startup_endpoint();

    void
    register_commands(std::shared_ptr<oxen::quic::BTRequestStream>& s);

   public:
    const link::Endpoint&
    endpoint()
    {
      return ep;
    }

    const oxen::quic::Address&
    local()
    {
      return addr;
    }

    bool
    have_connection_to(const RouterID& remote, bool client_only = false) const;

    bool
    have_client_connection_to(const RouterID& remote) const;

    void
    deregister_peer(RouterID remote);

    void
    connect_to(const RouterID& router);

    void
    connect_to(const RouterContact& rc);

    void
    close_connection(RouterID rid);

    void
    stop();

    void
    set_conn_persist(const RouterID& remote, llarp_time_t until);

    size_t
    get_num_connected(bool clients_only = false) const;

    size_t
    get_num_connected_clients() const;

    bool
    get_random_connected(RouterContact& router) const;

    void
    check_persisting_conns(llarp_time_t now);

    void
    update_peer_db(std::shared_ptr<PeerDb> peerDb);

    util::StatusObject
    extract_status() const;

    void
    init(RCLookupHandler* rcLookup);

    void
    for_each_connection(std::function<void(link::Connection&)> func);

    // Attempts to connect to a number of random routers.
    //
    // This will try to connect to *up to* num_conns routers, but will not
    // check if we already have a connection to any of the random set, as making
    // that thread safe would be slow...I think.
    void
    connect_to_random(int num_conns);

    // TODO: tune these (maybe even remove max?) now that we're switching to quic
    /// always maintain this many connections to other routers
    size_t min_connected_routers = 4;
    /// hard upperbound limit on the number of router to router connections
    size_t max_connected_routers = 6;

   private:
    // DHT messages
    void handle_find_name(oxen::quic::message, const RouterID& from);      // relay
    void handle_find_intro(oxen::quic::message, const RouterID& from);     // relay
    void handle_publish_intro(oxen::quic::message, const RouterID& from);  // relay
    void handle_find_router(oxen::quic::message, const RouterID& from);    // relay + path

    // Path messages
    void handle_path_build(oxen::quic::message, const RouterID& from);     // relay
    void handle_path_confirm(oxen::quic::message, const RouterID& from);   // relay
    void handle_path_latency(oxen::quic::message, const RouterID& from);   // relay
    void handle_path_transfer(oxen::quic::message, const RouterID& from);  // relay

    // Exit messages
    void handle_obtain_exit(oxen::quic::message, const RouterID& from);  // relay
    void handle_update_exit(oxen::quic::message, const RouterID& from);  // relay
    void handle_close_exit(oxen::quic::message, const RouterID& from);   // relay

    std::unordered_map<std::string, void (LinkManager::*)(oxen::quic::message)> rpc_commands = {
        {"find_name", &LinkManager::handle_find_name},
        {"find_router", &LinkManager::handle_find_router},
        {"publish_intro", &LinkManager::handle_publish_intro},
        {"find_intro", &LinkManager::handle_find_intro},
        {"path_build", &LinkManager::handle_path_build},
        {"path_confirm", &LinkManager::handle_path_confirm},
        {"path_latency", &LinkManager::handle_path_latency},
        {"update_exit", &LinkManager::handle_update_exit},
        {"obtain_exit", &LinkManager::handle_obtain_exit},
        {"close_exit", &LinkManager::handle_close_exit}};

    // DHT responses
    void handle_find_name_response(oxen::quic::message);
    void handle_find_intro_response(oxen::quic::message);
    void handle_publish_intro_response(oxen::quic::message);
    void handle_find_router_response(oxen::quic::message);

    // Path responses
    void handle_path_build_response(oxen::quic::message);
    void handle_relay_commit_response(oxen::quic::message);
    void handle_relay_status_response(oxen::quic::message);
    void handle_path_confirm_response(oxen::quic::message);
    void handle_path_latency_response(oxen::quic::message);
    void handle_path_transfer_response(oxen::quic::message);

    // Exit responses
    void handle_obtain_exit_response(oxen::quic::message);
    void handle_update_exit_response(oxen::quic::message);
    void handle_close_exit_response(oxen::quic::message);

    std::unordered_map<std::string, void (LinkManager::*)(oxen::quic::message)> rpc_responses = {
        {"find_name", &LinkManager::handle_find_name_response},
        {"find_router", &LinkManager::handle_find_router_response},
        {"publish_intro", &LinkManager::handle_publish_intro_response},
        {"find_intro", &LinkManager::handle_find_intro_response},
        {"update_exit", &LinkManager::handle_update_exit_response},
        {"obtain_exit", &LinkManager::handle_obtain_exit_response},
        {"close_exit", &LinkManager::handle_close_exit_response}};

    std::string
    serialize_response(oxenc::bt_dict supplement = {});

   public:
    // Public response functions and error handling functions invoked elsehwere. These take
    // r-value references s.t. that message is taken out of calling scope
    void
    handle_find_router_error(oxen::quic::message&& m);
  };

  namespace link
  {
    template <typename... Opt>
    bool
    Endpoint::establish_connection(
        const oxen::quic::Address& remote, const RouterContact& rc, Opt&&... opts)
    {
      try
      {
        auto conn_interface =
            endpoint->connect(remote, link_manager.tls_creds, std::forward<Opt>(opts)...);

        // emplace immediately for connection open callback to find scid
        connid_map.emplace(conn_interface->scid(), rc.pubkey);
        auto [itr, b] = conns.emplace(rc.pubkey, nullptr);

        auto control_stream =
            conn_interface->template get_new_stream<oxen::quic::BTRequestStream>();
        itr->second = std::make_shared<link::Connection>(conn_interface, control_stream, rc);

        return true;
      }
      catch (...)
      {
        log::error(quic_cat, "Error: failed to establish connection to {}", remote);
        return false;
      }
    }
  }  // namespace link

}  // namespace llarp

/*
- Refactor RouterID to use gnutls info and maybe ConnectionID
- Combine routerID and connectionID to simplify mapping in llarp/link/endpoint.hpp
- Combine llarp/link/session.hpp into llarp/link/connection.hpp::Connection

- Combine llarp/link/server.hpp::ILinkLayer into llarp/link/endpoint.hpp::Endpoint
  - must maintain metadata storage, callbacks, etc

- If: one endpoint for ipv4 and ipv6
  - Then: can potentially combine:
    - llarp/link/endpoint.hpp
    - llarp/link/link_manager.hpp
    - llarp/link/outbound_message_handler.hpp
    - llarp/link/outbound_session_maker.hpp

  -> Yields mega-combo endpoint managing object?
    - Can avoid "kitchen sink" by greatly reducing complexity of implementation

  llarp/router/outbound_message_handler.hpp
    - pendingsessionmessagequeue
      - establish queue of messages to be sent on a connection we are creating
      - upon creation, send these messages in the connection established callback
    - if connection times out, flush queue
    - TOCHECK: is priority used at all??


std::unordered_map<std::string, void (llarp::link::LinkManager::*)(oxen::quic::message)>
rpc_commands = {
    {"find_name", &handle_find_name},
    {"find_router", &handle_find_router},
    // ...
};

for (const auto& [name, mfn] : rpc_commands)
    bparser.add_command(name, [this, mfn] (oxen::quic::message m) {
        router->call([this, mfn, m=std::move(m)] mutable {
            try {
                std::invoke(mfn, this, std::move(m));
            } catch (const std::exception& e) {
                m.respond("Error: "s + e.what(), true);
            }
        });
    });

*/
