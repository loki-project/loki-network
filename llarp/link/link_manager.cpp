#include "link_manager.hpp"
#include "connection.hpp"
#include "contacts.hpp"

#include <llarp/messages/dht.hpp>
#include <llarp/messages/exit.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/router/router.hpp>
#include <llarp/router/rc_lookup_handler.hpp>
#include <llarp/nodedb.hpp>

#include <algorithm>
#include <set>

namespace llarp
{
  namespace link
  {
    std::shared_ptr<link::Connection>
    Endpoint::get_conn(const RouterContact& rc) const
    {
      if (auto itr = conns.find(rc.pubkey); itr != conns.end())
        return itr->second;

      return nullptr;
    }

    std::shared_ptr<link::Connection>
    Endpoint::get_conn(const RouterID& rid) const
    {
      if (auto itr = conns.find(rid); itr != conns.end())
        return itr->second;

      return nullptr;
    }

    bool
    Endpoint::have_conn(const RouterID& remote, bool client_only) const
    {
      if (auto itr = conns.find(remote); itr != conns.end())
      {
        if (not(itr->second->remote_is_relay and client_only))
          return true;
      }

      return false;
    }

    bool
    Endpoint::deregister_peer(RouterID _rid)
    {
      if (auto itr = conns.find(_rid); itr != conns.end())
      {
        auto& c = itr->second;
        auto& _scid = c->conn->scid();

        link_manager._router.loop()->call([this, scid = _scid, rid = _rid]() {
          endpoint->close_connection(scid);

          conns.erase(rid);
          connid_map.erase(scid);
        });

        return true;
      }

      return false;
    }

    size_t
    Endpoint::num_connected(bool clients_only) const
    {
      size_t count = 0;

      for (const auto& c : conns)
      {
        if (not(c.second->remote_is_relay and clients_only))
          count += 1;
      }

      return count;
    }

    bool
    Endpoint::get_random_connection(RouterContact& router) const
    {
      if (const auto size = conns.size(); size)
      {
        auto itr = conns.begin();
        std::advance(itr, randint() % size);
        router = itr->second->remote_rc;
        return true;
      }

      log::warning(quic_cat, "Error: failed to fetch random connection");
      return false;
    }

    void
    Endpoint::for_each_connection(std::function<void(link::Connection&)> func)
    {
      for (const auto& [rid, conn] : conns)
        func(*conn);
    }

    void
    Endpoint::close_connection(RouterID _rid)
    {
      if (auto itr = conns.find(_rid); itr != conns.end())
      {
        auto& c = itr->second;
        auto& _scid = c->conn->scid();

        link_manager._router.loop()->call([this, scid = _scid, rid = _rid]() {
          endpoint->close_connection(scid);

          conns.erase(rid);
          connid_map.erase(scid);
        });
      }
    }

  }  // namespace link

  void
  LinkManager::for_each_connection(std::function<void(link::Connection&)> func)
  {
    if (is_stopping)
      return;

    return ep.for_each_connection(func);
  }

  void
  LinkManager::register_commands(std::shared_ptr<oxen::quic::BTRequestStream>& s)
  {
    assert(ep.connid_map.contains(s.conn_id()));
    RouterID rid = ep.connid_map[s.conn_id()];
    for (const auto& [name, func] : rpc_commands)
    {
      s->register_command(name, [this, rid, &func](oxen::quic::message m) {
        _router.loop()->call([this, &func, &rid, msg = std::move(m)]() mutable {
          std::invoke(func, this, std::move(msg), rid);
        });
      });
    }
  }

  std::shared_ptr<oxen::quic::Endpoint>
  LinkManager::startup_endpoint()
  {
    /** Parameters:
          - local bind address
          - conection open callback
          - connection close callback
          - stream constructor callback
            - will return a BTRequestStream on the first call to get_new_stream<BTRequestStream>
    */
    auto ep = quic->endpoint(
        _router.public_ip(),
        [this](oxen::quic::connection_interface& ci) { return on_conn_open(ci); },
        [this](oxen::quic::connection_interface& ci, uint64_t ec) {
          return on_conn_closed(ci, ec);
        },
        [this](oxen::quic::dgram_interface& di, bstring dgram) { recv_data_message(di, dgram); });
    ep->listen(
        tls_creds,
        [&](oxen::quic::Connection& c,
            oxen::quic::Endpoint& e,
            std::optional<int64_t> id) -> std::shared_ptr<oxen::quic::Stream> {
          if (id && id == 0)
          {
            auto s = std::make_shared<oxen::quic::BTRequestStream>(c, e);
            register_commands(s);
            return s;
          }
          return std::make_shared<oxen::quic::Stream>(c, e);
        });
    return ep;
  }

  LinkManager::LinkManager(Router& r)
      : _router{r}
      , quic{std::make_unique<oxen::quic::Network>()}
      , tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_keys(
            {reinterpret_cast<const char*>(_router.identity().data()), size_t{32}},
            {reinterpret_cast<const char*>(_router.identity().toPublic().data()), size_t{32}})}
      , ep{startup_endpoint(), *this}
  {}

  bool
  LinkManager::send_control_message(
      const RouterID& remote,
      std::string endpoint,
      std::string body,
      std::function<void(oxen::quic::message m)> func)
  {
    if (not func and rpc_responses.count(endpoint))
    {
      func = [&](oxen::quic::message m) {
        std::invoke(rpc_responses[endpoint], this, std::move(m));
      };
    }

    if (func)
    {
      func = [this, f = std::move(func)](oxen::quic::message m) mutable {
        _router.loop()->call([func = std::move(f), msg = std::move(m)]() mutable { func(msg); });
      };
    }

    return send_control_message_impl(remote, std::move(endpoint), std::move(body), std::move(func));
  }

  bool
  LinkManager::send_control_message_impl(
      const RouterID& remote,
      std::string endpoint,
      std::string body,
      std::function<void(oxen::quic::message m)> func)
  {
    if (is_stopping)
      return false;

    if (auto conn = ep.get_conn(remote); conn)
    {
      conn->control_stream->command(std::move(endpoint), std::move(body), std::move(func));
      return true;
    }

    _router.loop()->call([this, remote, endpoint, body, f = std::move(func)]() {
      auto pending = PendingControlMessage(body, endpoint, f);

      auto [itr, b] = pending_conn_msg_queue.emplace(remote, MessageQueue());
      itr->second.push_back(std::move(pending));

      rc_lookup->get_rc(remote, [this]([[maybe_unused]] auto rid, auto rc, auto success) {
        if (success)
        {
          _router.node_db()->put_rc_if_newer(*rc);
          connect_to(*rc);
        }
        else
          log::warning(quic_cat, "Do something intelligent here for error handling");
      });
    });

    return false;
  }

  bool
  LinkManager::send_data_message(const RouterID& remote, std::string body)
  {
    if (is_stopping)
      return false;

    if (auto conn = ep.get_conn(remote); conn)
    {
      conn->conn->send_datagram(std::move(body));
      return true;
    }

    _router.loop()->call([&]() {
      auto pending = PendingDataMessage(body);

      auto [itr, b] = pending_conn_msg_queue.emplace(remote, MessageQueue());
      itr->second.push_back(std::move(pending));

      rc_lookup->get_rc(remote, [this]([[maybe_unused]] auto rid, auto rc, auto success) {
        if (success)
        {
          _router.node_db()->put_rc_if_newer(*rc);
          connect_to(*rc);
        }
        else
          log::warning(quic_cat, "Do something intelligent here for error handling");
      });
    });

    return false;
  }

  void
  LinkManager::close_connection(RouterID rid)
  {
    return ep.close_connection(rid);
  }

  void
  LinkManager::connect_to(const RouterID& rid)
  {
    rc_lookup->get_rc(rid, [this]([[maybe_unused]] auto rid, auto rc, auto success) {
      if (success)
      {
        _router.node_db()->put_rc_if_newer(*rc);
        connect_to(*rc);
      }
      else
        log::warning(quic_cat, "Do something intelligent here for error handling");
    });
  }

  // This function assumes the RC has already had its signature verified and connection is allowed.
  void
  LinkManager::connect_to(const RouterContact& rc)
  {
    if (auto conn = ep.get_conn(rc.pubkey); conn)
    {
      // TODO: should implement some connection failed logic, but not the same logic that
      // would be executed for another failure case
      return;
    }

    auto& remote_addr = rc.addr;

    // TODO: confirm remote end is using the expected pubkey (RouterID).
    // TODO: ALPN for "client" vs "relay" (could just be set on endpoint creation)
    if (auto rv = ep.establish_connection(remote_addr, rc); rv)
    {
      log::info(quic_cat, "Connection to {} successfully established!", remote_addr);
      return;
    }
    log::warning(quic_cat, "Connection to {} successfully established!", remote_addr);
  }

  // TODO: should we add routes here now that Router::SessionOpen is gone?
  void
  LinkManager::on_conn_open(oxen::quic::connection_interface& ci)
  {
    _router.loop()->call([this, &conn_interface = ci]() {
      const auto& scid = conn_interface.scid();
      const auto& rid = ep.connid_map[scid];

      // check to see if this connection was established while we were attempting to queue
      // messages to the remote
      if (auto itr = pending_conn_msg_queue.find(rid); itr != pending_conn_msg_queue.end())
      {
        auto& que = itr->second;

        while (not que.empty())
        {
          auto& m = que.front();

          if (m.is_control)
          {
            auto& msg = reinterpret_cast<PendingControlMessage&>(m);
            ep.conns[rid]->control_stream->command(msg.endpoint, msg.body, msg.func);
          }
          else
          {
            auto& msg = reinterpret_cast<PendingDataMessage&>(m);
            conn_interface.send_datagram(std::move(msg.body));
          }

          que.pop_front();
        }
      }
    });
  };

  void
  LinkManager::on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec)
  {
    _router.loop()->call([this, &conn_interface = ci, error_code = ec]() {
      const auto& scid = conn_interface.scid();

      log::debug(quic_cat, "Purging quic connection CID:{} (ec: {})", scid, error_code);

      if (const auto& c_itr = ep.connid_map.find(scid); c_itr != ep.connid_map.end())
      {
        const auto& rid = c_itr->second;

        if (auto p_itr = pending_conn_msg_queue.find(rid); p_itr != pending_conn_msg_queue.end())
          pending_conn_msg_queue.erase(p_itr);

        if (auto m_itr = ep.conns.find(rid); m_itr != ep.conns.end())
          ep.conns.erase(m_itr);

        ep.connid_map.erase(c_itr);

        log::debug(quic_cat, "Quic connection CID:{} purged successfully", scid);
      }
    });
  }

  bool
  LinkManager::have_connection_to(const RouterID& remote, bool client_only) const
  {
    return ep.have_conn(remote, client_only);
  }

  bool
  LinkManager::have_client_connection_to(const RouterID& remote) const
  {
    return ep.have_conn(remote, true);
  }

  void
  LinkManager::deregister_peer(RouterID remote)
  {
    if (auto rv = ep.deregister_peer(remote); rv)
    {
      persisting_conns.erase(remote);
      log::info(logcat, "Peer {} successfully de-registered", remote);
    }
    else
      log::warning(logcat, "Peer {} not found for de-registration!", remote);
  }

  void
  LinkManager::stop()
  {
    if (is_stopping)
    {
      return;
    }

    util::Lock l(m);

    LogInfo("stopping links");
    is_stopping = true;

    quic.reset();
  }

  void
  LinkManager::set_conn_persist(const RouterID& remote, llarp_time_t until)
  {
    if (is_stopping)
      return;

    util::Lock l(m);

    persisting_conns[remote] = std::max(until, persisting_conns[remote]);
    if (have_client_connection_to(remote))
    {
      // mark this as a client so we don't try to back connect
      clients.Upsert(remote);
    }
  }

  size_t
  LinkManager::get_num_connected(bool clients_only) const
  {
    return ep.num_connected(clients_only);
  }

  size_t
  LinkManager::get_num_connected_clients() const
  {
    return get_num_connected(true);
  }

  bool
  LinkManager::get_random_connected(RouterContact& router) const
  {
    return ep.get_random_connection(router);
  }

  // TODO: this?  perhaps no longer necessary in the same way?
  void
  LinkManager::check_persisting_conns(llarp_time_t)
  {
    if (is_stopping)
      return;
  }

  // TODO: do we still need this concept?
  void
  LinkManager::update_peer_db(std::shared_ptr<PeerDb>)
  {}

  // TODO: this
  util::StatusObject
  LinkManager::extract_status() const
  {
    return {};
  }

  void
  LinkManager::init(RCLookupHandler* rcLookup)
  {
    is_stopping = false;
    rc_lookup = rcLookup;
    node_db = _router.node_db();
  }

  void
  LinkManager::connect_to_random(int num_conns)
  {
    std::set<RouterID> exclude;
    auto remainder = num_conns;

    do
    {
      auto filter = [exclude](const auto& rc) -> bool { return exclude.count(rc.pubkey) == 0; };

      if (auto maybe_other = node_db->GetRandom(filter))
      {
        exclude.insert(maybe_other->pubkey);

        if (not rc_lookup->is_session_allowed(maybe_other->pubkey))
          continue;

        connect_to(*maybe_other);
        --remainder;
      }
    } while (remainder > 0);
  }

  void
  LinkManager::recv_data_message(oxen::quic::dgram_interface&, bstring)
  {
    // TODO: this
  }

  std::string
  LinkManager::serialize_response(oxenc::bt_dict supplement)
  {
    return oxenc::bt_serialize(supplement);
  }

  void
  LinkManager::handle_find_name(oxen::quic::message m, const RouterID& from)
  {
    std::string name_hash;

    try
    {
      oxenc::bt_dict_consumer btdp{m.body()};

      name_hash = btdp.require<std::string>("H");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", FindNameMessage::EXCEPTION}}), true);
    }

    _router.rpc_client()->lookup_ons_hash(
        name_hash,
        [this,
         msg = std::move(m)]([[maybe_unused]] std::optional<service::EncryptedName> maybe) mutable {
          if (maybe)
            msg.respond(serialize_response({{"NAME", maybe->ciphertext}}));
          else
            msg.respond(serialize_response({{"STATUS", FindNameMessage::NOT_FOUND}}), true);
        });
  }

  void
  LinkManager::handle_find_name_response(oxen::quic::message m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "FindNameMessage timed out!");
      return;
    }

    std::string payload;

    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
      payload = btdc.require<std::string>(m ? "NAME" : "STATUS");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      return;
    }

    if (m)
    {
      // TODO: wtf
    }
    else
    {
      if (payload == FindNameMessage::EXCEPTION)
      {
        log::info(link_cat, "FindNameMessage failed with unkown error!");

        // resend?
      }
      else if (payload == FindNameMessage::NOT_FOUND)
      {
        log::info(link_cat, "FindNameMessage failed with unkown error!");
        // what to do here?
      }
      else
        log::info(link_cat, "FindNameMessage failed with unkown error!");
    }
  }

  // TODO: add callback to relayed messages (calls to send_control_message so the
  // response finds its way back)
  void
  LinkManager::handle_find_router(oxen::quic::message m, const RouterID& from)
  {
    std::string target_key;
    bool is_exploratory, is_iterative;

    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};

      is_exploratory = btdc.require<bool>("E");
      is_iterative = btdc.require<bool>("I");
      target_key = btdc.require<std::string>("K");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(
          serialize_response({{"STATUS", FindRouterMessage::EXCEPTION}, {"TARGET", ""}}), true);
      return;
    }

    // TODO: do we need a replacement for dht.AllowTransit() etc here?

    RouterID target_rid;
    target_rid.FromString(target_key);

    const auto target_addr = dht::Key_t{reinterpret_cast<uint8_t*>(target_key.data())};
    const auto& local_rid = _router.rc().pubkey;
    const auto local_key = dht::Key_t{local_rid};

    if (is_exploratory)
    {
      std::string neighbors{};
      const auto closest_rcs =
          _router.node_db()->find_many_closest_to(target_addr, RC_LOOKUP_STORAGE_REDUNDANCY);

      for (const auto& rc : closest_rcs)
      {
        const auto& rid = rc.pubkey;
        if (_router.router_profiling().IsBadForConnect(rid) || target_rid == rid
            || local_rid == rid)
          continue;

        neighbors += rid.bt_encode();
      }

      m.respond(
          serialize_response({{"STATUS", FindRouterMessage::RETRY_EXP}, {"TARGET", neighbors}}),
          true);
    }
    else
    {
      const auto closest_rc = _router.node_db()->find_closest_to(target_addr);
      const auto& closest_rid = closest_rc.pubkey;
      const auto closest_key = dht::Key_t{closest_rid};

      if (target_addr == closest_key)
      {
        if (closest_rc.ExpiresSoon(llarp::time_now_ms()))
        {
          send_control_message(
              target_rid,
              "find_router",
              FindRouterMessage::serialize(target_rid, false, false),
              [original = std::move(m)](oxen::quic::message msg) mutable {
                original.respond(msg.body_str(), not msg);
              });
        }
        else
        {
          m.respond(serialize_response({{"RC", closest_rc.bt_encode()}}));
        }
      }
      else if (not is_iterative)
      {
        if ((closest_key ^ target_addr) < (local_key ^ target_addr))
        {
          send_control_message(
              closest_rid,
              "find_router",
              FindRouterMessage::serialize(closest_rid, false, false),
              [original = std::move(m)](oxen::quic::message msg) mutable {
                original.respond(msg.body_str(), not msg);
              });
        }
        else
        {
          m.respond(
              serialize_response(
                  {{"STATUS", FindRouterMessage::RETRY_ITER}, {"TARGET", target_addr.data()}}),
              true);
        }
      }
      else
      {
        m.respond(
            serialize_response(
                {{"STATUS", FindRouterMessage::RETRY_NEW},
                 {"TARGET", reinterpret_cast<const char*>(closest_rid.data())}}),
            true);
      }
    }
  }

  void
  LinkManager::handle_find_router_response(oxen::quic::message m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "FindRouterMessage timed out!");
      return;
    }

    std::string status, payload;

    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};

      if (m)
        payload = btdc.require<std::string>("RC");
      else
      {
        payload = btdc.require<std::string>("RECIPIENT");
        status = btdc.require<std::string>("TARGET");
      }
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      return;
    }

    if (m)
    {
      _router.node_db()->put_rc_if_newer(RouterContact{payload});
    }
    else
    {
      if (status == FindRouterMessage::EXCEPTION)
      {
        log::info(link_cat, "FindRouterMessage failed with remote exception!");
        // Do something smart here probably
        return;
      }

      RouterID target{reinterpret_cast<uint8_t*>(payload.data())};

      if (status == FindRouterMessage::RETRY_EXP)
      {
        log::info(link_cat, "FindRouterMessage failed, retrying as exploratory!");
        send_control_message(
            target, "find_router", FindRouterMessage::serialize(target, false, true));
      }
      else if (status == FindRouterMessage::RETRY_ITER)
      {
        log::info(link_cat, "FindRouterMessage failed, retrying as iterative!");
        send_control_message(
            target, "find_router", FindRouterMessage::serialize(target, true, false));
      }
      else if (status == FindRouterMessage::RETRY_NEW)
      {
        log::info(link_cat, "FindRouterMessage failed, retrying with new recipient!");
        send_control_message(
            target, "find_router", FindRouterMessage::serialize(target, false, false));
      }
    }
  }

  void
  LinkManager::handle_find_router_error(oxen::quic::message&& m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "FindRouterMessage timed out!");
      return;
    }

    std::string status, payload;

    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};

      payload = btdc.require<std::string>("RECIPIENT");
      status = btdc.require<std::string>("TARGET");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      return;
    }

    if (status == FindRouterMessage::EXCEPTION)
    {
      log::info(link_cat, "FindRouterMessage failed with remote exception!");
      // Do something smart here probably
      return;
    }

    RouterID target{reinterpret_cast<uint8_t*>(payload.data())};

    if (status == FindRouterMessage::RETRY_EXP)
    {
      log::info(link_cat, "FindRouterMessage failed, retrying as exploratory!");
      send_control_message(
          target, "find_router", FindRouterMessage::serialize(target, false, true));
    }
    else if (status == FindRouterMessage::RETRY_ITER)
    {
      log::info(link_cat, "FindRouterMessage failed, retrying as iterative!");
      send_control_message(
          target, "find_router", FindRouterMessage::serialize(target, true, false));
    }
    else if (status == FindRouterMessage::RETRY_NEW)
    {
      log::info(link_cat, "FindRouterMessage failed, retrying with new recipient!");
      send_control_message(
          target, "find_router", FindRouterMessage::serialize(target, false, false));
    }
  }

  void
  LinkManager::handle_publish_intro(oxen::quic::message m, const RouterID& from)
  {
    std::string introset, derived_signing_key, payload, sig, nonce;
    uint64_t is_relayed, relay_order;
    std::chrono::milliseconds signed_at;

    try
    {
      oxenc::bt_dict_consumer btdc_a{m.body()};

      introset = btdc_a.require<std::string>("I");
      relay_order = btdc_a.require<uint64_t>("O");
      is_relayed = btdc_a.require<uint64_t>("R");

      oxenc::bt_dict_consumer btdc_b{introset.data()};

      derived_signing_key = btdc_b.require<std::string>("d");
      nonce = btdc_b.require<std::string>("n");
      signed_at = std::chrono::milliseconds{btdc_b.require<uint64_t>("s")};
      payload = btdc_b.require<std::string>("x");
      sig = btdc_b.require<std::string>("z");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", PublishIntroMessage::EXCEPTION}}), true);
      return;
    }

    const auto now = _router.now();
    const auto addr = dht::Key_t{reinterpret_cast<uint8_t*>(derived_signing_key.data())};
    const auto local_key = _router.rc().pubkey;

    if (not service::EncryptedIntroSet::verify(introset, derived_signing_key, sig))
    {
      log::error(link_cat, "Received PublishIntroMessage with invalid introset: {}", introset);
      m.respond(serialize_response({{"STATUS", PublishIntroMessage::INVALID_INTROSET}}), true);
      return;
    }

    if (now + service::MAX_INTROSET_TIME_DELTA > signed_at + path::DEFAULT_LIFETIME)
    {
      log::error(link_cat, "Received PublishIntroMessage with expired introset: {}", introset);
      m.respond(serialize_response({{"STATUS", PublishIntroMessage::EXPIRED}}), true);
      return;
    }

    auto closest_rcs = _router.node_db()->find_many_closest_to(addr, INTROSET_STORAGE_REDUNDANCY);

    if (closest_rcs.size() != INTROSET_STORAGE_REDUNDANCY)
    {
      log::error(
          link_cat, "Received PublishIntroMessage but only know {} nodes", closest_rcs.size());
      m.respond(serialize_response({{"STATUS", PublishIntroMessage::INSUFFICIENT}}), true);
      return;
    }

    service::EncryptedIntroSet enc{derived_signing_key, signed_at, payload, nonce, sig};

    if (is_relayed)
    {
      if (relay_order >= INTROSET_STORAGE_REDUNDANCY)
      {
        log::error(
            link_cat, "Received PublishIntroMessage with invalide relay order: {}", relay_order);
        m.respond(serialize_response({{"STATUS", PublishIntroMessage::INVALID_ORDER}}), true);
        return;
      }

      log::info(link_cat, "Relaying PublishIntroMessage for {}", addr);

      const auto& peer_rc = closest_rcs[relay_order];
      const auto& peer_key = peer_rc.pubkey;

      if (peer_key == local_key)
      {
        log::info(
            link_cat,
            "Received PublishIntroMessage in which we are peer index {}.. storing introset",
            relay_order);

        _router.contacts()->services()->PutNode(dht::ISNode{std::move(enc)});
        m.respond(serialize_response({{"STATUS", ""}}));
      }
      else
      {
        log::info(
            link_cat, "Received PublishIntroMessage; propagating to peer index {}", relay_order);

        send_control_message(
            peer_key,
            "publish_intro",
            PublishIntroMessage::serialize(introset, relay_order, is_relayed));
      }

      return;
    }

    int rc_index = -1, index = 0;

    for (const auto& rc : closest_rcs)
    {
      if (rc.pubkey == local_key)
      {
        rc_index = index;
        break;
      }
      ++index;
    }

    if (rc_index >= 0)
    {
      log::info(link_cat, "Received PublishIntroMessage for {} (TXID: {}); we are candidate {}");

      _router.contacts()->services()->PutNode(dht::ISNode{std::move(enc)});
      m.respond(serialize_response());
    }
    else
      log::warning(
          link_cat,
          "Received non-relayed PublishIntroMessage from {}; we are not the candidate",
          addr);
  }

  void
  LinkManager::handle_publish_intro_response(oxen::quic::message m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "PublishIntroMessage timed out!");
      return;
    }

    std::string payload;

    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
      payload = btdc.require<std::string>("STATUS");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      return;
    }

    if (m)
    {
      // DISCUSS: not sure what to do on success of a publish intro command?
    }
    else
    {
      if (payload == PublishIntroMessage::EXCEPTION)
      {
        log::info(link_cat, "PublishIntroMessage failed with remote exception!");
        // Do something smart here probably
        return;
      }

      log::info(link_cat, "PublishIntroMessage failed with error code: {}", payload);

      if (payload == PublishIntroMessage::INVALID_INTROSET)
      {}
      else if (payload == PublishIntroMessage::EXPIRED)
      {}
      else if (payload == PublishIntroMessage::INSUFFICIENT)
      {}
      else if (payload == PublishIntroMessage::INVALID_ORDER)
      {}
    }
  }

  void
  LinkManager::handle_find_intro(oxen::quic::message m, const RouterID& from)
  {
    ustring location;
    uint64_t relay_order, is_relayed;

    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};

      relay_order = btdc.require<uint64_t>("O");
      is_relayed = btdc.require<uint64_t>("R");
      location = btdc.require<ustring>("S");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", FindIntroMessage::EXCEPTION}}), true);
      return;
    }

    const auto addr = dht::Key_t{location.data()};

    if (is_relayed)
    {
      if (relay_order >= INTROSET_STORAGE_REDUNDANCY)
      {
        log::warning(
            link_cat, "Received FindIntroMessage with invalid relay order: {}", relay_order);
        m.respond(serialize_response({{"STATUS", FindIntroMessage::INVALID_ORDER}}), true);
        return;
      }

      auto closest_rcs = _router.node_db()->find_many_closest_to(addr, INTROSET_STORAGE_REDUNDANCY);

      if (closest_rcs.size() != INTROSET_STORAGE_REDUNDANCY)
      {
        log::error(
            link_cat, "Received FindIntroMessage but only know {} nodes", closest_rcs.size());
        m.respond(serialize_response({{"STATUS", FindIntroMessage::INSUFFICIENT_NODES}}), true);
        return;
      }

      log::info(link_cat, "Relaying FindIntroMessage for {}", addr);

      const auto& peer_rc = closest_rcs[relay_order];
      const auto& peer_key = peer_rc.pubkey;

      send_control_message(
          peer_key,
          "find_intro",
          FindIntroMessage::serialize(dht::Key_t{peer_key}, is_relayed, relay_order),
          [original_msg = std::move(m)](oxen::quic::message relay_response) mutable {
            if (relay_response)
              log::info(
                  link_cat,
                  "Relayed FindIntroMessage returned successful response; transmitting to initial "
                  "requester");
            else if (relay_response.timed_out)
              log::critical(
                  link_cat, "Relayed FindIntroMessage timed out! Notifying initial requester");
            else
              log::critical(
                  link_cat, "Relayed FindIntroMessage failed! Notifying initial requester");

            original_msg.respond(relay_response.body_str(), not relay_response);
          });
    }
    else
    {
      if (auto maybe_intro = _router.contacts()->get_introset_by_location(addr))
        m.respond(serialize_response({{"INTROSET", maybe_intro->bt_encode()}}));
      else
      {
        log::warning(
            link_cat,
            "Received FindIntroMessage with relayed == false and no local introset entry");
        m.respond(serialize_response({{"STATUS", FindIntroMessage::NOT_FOUND}}), true);
      }
    }
  }

  void
  LinkManager::handle_find_intro_response(oxen::quic::message m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "FindIntroMessage timed out!");
      return;
    }

    std::string payload;

    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
      payload = btdc.require<std::string>((m) ? "INTROSET" : "STATUS");
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      return;
    }

    // success case, neither timed out nor errored
    if (m)
    {
      service::EncryptedIntroSet enc{payload};
      _router.contacts()->services()->PutNode(std::move(enc));
    }
    else
    {
      log::info(link_cat, "FindIntroMessage failed with error: {}", payload);
      // Do something smart here probably
    }
  }

  void
  LinkManager::handle_path_build(oxen::quic::message m, const RouterID& from)
  {
    if (!_router.path_context().AllowingTransit())
    {
      log::warning(link_cat, "got path build request when not permitting transit");
      m.respond(serialize_response({{"STATUS", PathBuildMessage::NO_TRANSIT}}), true);
      return;
    }
    try
    {
      std::string payload{m.body()}, frame_payload;
      std::string frame, hash, hop_payload, commkey, rx_id, tx_id, upstream;
      ustring other_pubkey, outer_nonce, inner_nonce;
      uint64_t lifetime;

      auto crypto = CryptoManager::instance();

      try
      {
        oxenc::bt_list_consumer btlc{payload};
        frame_payload = btlc.consume_string();

        oxenc::bt_dict_consumer frame_info{frame_payload};
        hash = frame_info.require<std::string>("HASH");
        frame = frame_info.require<std::string>("FRAME");

        oxenc::bt_dict_consumer hop_dict{frame};
        hop_payload = frame_info.require<std::string>("ENCRYPTED");
        outer_nonce = frame_info.require<ustring>("NONCE");
        other_pubkey = frame_info.require<ustring>("PUBKEY");

        SharedSecret shared;
        // derive shared secret using ephemeral pubkey and our secret key (and nonce)
        if (!crypto->dh_server(
                shared.data(), other_pubkey.data(), _router.pubkey(), inner_nonce.data()))
        {
          log::info(link_cat, "DH server initialization failed during path build");
          m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_CRYPTO}}), true);
          return;
        }

        // hash data and check against given hash
        ShortHash digest;
        if (!crypto->hmac(
                digest.data(),
                reinterpret_cast<unsigned char*>(frame.data()),
                frame.size(),
                shared))
        {
          log::error(link_cat, "HMAC failed on path build request");
          m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_CRYPTO}}), true);
          return;
        }
        if (!std::equal(
                digest.begin(), digest.end(), reinterpret_cast<const unsigned char*>(hash.data())))
        {
          log::info(link_cat, "HMAC mismatch on path build request");
          m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_CRYPTO}}), true);
          return;
        }

        // decrypt frame with our hop info
        if (!crypto->xchacha20(
                reinterpret_cast<unsigned char*>(hop_payload.data()),
                hop_payload.size(),
                shared.data(),
                outer_nonce.data()))
        {
          log::info(link_cat, "Decrypt failed on path build request");
          m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_CRYPTO}}), true);
          return;
        }

        oxenc::bt_dict_consumer hop_info{hop_payload};
        commkey = hop_info.require<std::string>("COMMKEY");
        lifetime = hop_info.require<uint64_t>("LIFETIME");
        inner_nonce = hop_info.require<ustring>("NONCE");
        rx_id = hop_info.require<std::string>("RX");
        tx_id = hop_info.require<std::string>("TX");
        upstream = hop_info.require<std::string>("UPSTREAM");
      }
      catch (...)
      {
        log::warning(link_cat, "Error: failed to deserialize path build message");
        throw;
      }

      if (frame.empty())
      {
        log::info(link_cat, "Path build request received invalid frame");
        m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_FRAMES}}), true);
        return;
      }

      // populate transit hop object with hop info
      // TODO: IP / path build limiting clients
      auto hop = std::make_shared<path::TransitHop>();
      hop->info.downstream = m.from();

      // extract pathIDs and check if zero or used
      auto& hop_info = hop->info;
      hop_info.txID.from_string_view(tx_id);
      hop_info.rxID.from_string_view(rx_id);

      if (hop_info.txID.IsZero() || hop_info.rxID.IsZero())
      {
        log::warning(link_cat, "Invalid PathID; PathIDs must be non-zero");
        m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_PATHID}}), true);
        return;
      }

      hop_info.upstream.from_string_view(upstream);

      // TODO: the whole transit hop container is garbage.
      //       namely the PathID uniqueness checking uses the PathIDs and upstream/downstream
      //       but if someone made a path with txid, rxid, and downstream the same but
      //       a different upstream, that would be "unique" but we wouldn't know where
      //       to route messages.
      if (_router.path_context().HasTransitHop(hop_info))
      {
        log::warning(link_cat, "Invalid PathID; PathIDs must be unique");
        m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_PATHID}}), true);
        return;
      }

      if (!crypto->dh_server(
              hop->pathKey.data(), other_pubkey.data(), _router.pubkey(), inner_nonce.data()))
      {
        log::warning(link_cat, "DH failed during path build.");
        m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_CRYPTO}}), true);
        return;
      }
      // generate hash of hop key for nonce mutation
      crypto->shorthash(hop->nonceXOR, hop->pathKey.data(), hop->pathKey.size());

      // set and check path lifetime
      hop->lifetime = 1ms * lifetime;

      if (hop->lifetime >= path::DEFAULT_LIFETIME)
      {
        log::warning(link_cat, "Path build attempt with too long of a lifetime.");
        m.respond(serialize_response({{"STATUS", PathBuildMessage::BAD_LIFETIME}}), true);
        return;
      }

      hop->started = _router.now();
      _router.persist_connection_until(hop_info.downstream, hop->ExpireTime() + 10s);

      if (hop_info.upstream == _router.pubkey())
      {
        // we are terminal hop and everything is okay
        _router.path_context().PutTransitHop(hop);
        m.respond(serialize_response({{"STATUS", PathBuildMessage::OK}}), false);
        return;
      }

      // rotate our frame to the end of the list and forward upstream
      auto payload_list = oxenc::bt_deserialize<oxenc::bt_list>(payload);
      payload_list.splice(payload_list.end(), payload_list, payload_list.begin());

      send_control_message(
          hop->info.upstream,
          "path_build",
          bt_serialize(payload_list),
          [hop, this, prev_message = std::move(m)](oxen::quic::message m) {
            if (m)
            {
              log::info(
                  link_cat,
                  "Upstream returned successful path build response; giving hop info to Router, "
                  "then relaying response");
              _router.path_context().PutTransitHop(hop);
            }
            if (m.timed_out)
              log::info(link_cat, "Upstream timed out on path build; relaying timeout");
            else
              log::info(link_cat, "Upstream returned path build failure; relaying response");

            m.respond(m.body_str(), not m);
          });
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", PathBuildMessage::EXCEPTION}}), true);
      return;
    }
  }

  void
  LinkManager::handle_path_build_response(oxen::quic::message m)
  {
    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      // m.respond(serialize_response({{"STATUS", "EXCEPTION"}}), true);
      return;
    }
  }

  void
  LinkManager::handle_path_confirm(oxen::quic::message m, const RouterID& from)
  {
    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", "EXCEPTION"}}), true);
      return;
    }
  }

  void
  LinkManager::handle_path_confirm_response(oxen::quic::message m)
  {
    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      // m.respond(serialize_response({{"STATUS", "EXCEPTION"}}), true);
      return;
    }
  }

  void
  LinkManager::handle_path_latency(oxen::quic::message m, const RouterID& from)
  {
    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", "EXCEPTION"}}), true);
      return;
    }
  }

  void
  LinkManager::handle_path_latency_response(oxen::quic::message m)
  {
    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      // m.respond(serialize_response({{"STATUS", "EXCEPTION"}}), true);
      return;
    }
  }

  void
  LinkManager::handle_path_transfer(oxen::quic::message m, const RouterID& from)
  {
    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", "EXCEPTION"}}), true);
      return;
    }
  }

  void
  LinkManager::handle_path_transfer_response(oxen::quic::message m)
  {
    try
    {
      oxenc::bt_dict_consumer btdc{m.body()};
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", "EXCEPTION"}}), true);
      return;
    }
  }

  void
  LinkManager::handle_obtain_exit(oxen::quic::message m, const RouterID& from)
  {
    try
    {
      uint64_t flag;
      ustring_view pubkey, sig;
      std::string_view tx_id;

      oxenc::bt_list_consumer btlc{m.body()};
      auto dict_data = btlc.consume_dict_data();
      oxenc::bt_dict_consumer btdc{dict_data};

      sig = to_usv(btlc.consume_string_view());
      flag = btdc.require<uint64_t>("E");
      pubkey = btdc.require<ustring_view>("I");
      tx_id = btdc.require<std::string_view>("T");

      RouterID target{pubkey.data()};
      auto transit_hop = std::static_pointer_cast<path::TransitHop>(
          _router.path_context().GetByUpstream(target, PathID_t{to_usv(tx_id).data()}));

      const auto rx_id = transit_hop->info.rxID;

      auto success =
          (CryptoManager::instance()->verify(pubkey, to_usv(dict_data), sig)
           and _router.exitContext().ObtainNewExit(PubKey{pubkey.data()}, rx_id, flag != 0));

      m.respond(
          ObtainExitMessage::sign_and_serialize_response(_router.identity(), tx_id), not success);
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", ObtainExitMessage::EXCEPTION}}), true);
      throw;
    }
  }

  void
  LinkManager::handle_obtain_exit_response(oxen::quic::message m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "ObtainExitMessage timed out!");
      return;
    }
    if (m.is_error)
    {
      // TODO: what to do here
    }

    try
    {
      std::string_view tx_id;
      ustring_view sig;

      oxenc::bt_list_consumer btlc{m.body()};
      auto dict_data = btlc.consume_dict_data();
      oxenc::bt_dict_consumer btdc{dict_data};

      sig = to_usv(btlc.consume_string_view());
      tx_id = btdc.require<std::string_view>("T");

      auto path_ptr = std::static_pointer_cast<path::Path>(
          _router.path_context().GetByDownstream(_router.pubkey(), PathID_t{to_usv(tx_id).data()}));

      if (CryptoManager::instance()->verify(_router.pubkey(), to_usv(dict_data), sig))
        path_ptr->enable_exit_traffic();
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      throw;
    }
  }

  void
  LinkManager::handle_update_exit(oxen::quic::message m, const RouterID& from)
  {
    try
    {
      std::string_view path_id, tx_id;
      ustring_view sig;

      oxenc::bt_list_consumer btlc{m.body()};
      auto dict_data = btlc.consume_dict_data();
      oxenc::bt_dict_consumer btdc{dict_data};

      sig = to_usv(btlc.consume_string_view());
      path_id = btdc.require<std::string_view>("P");
      tx_id = btdc.require<std::string_view>("T");

      auto transit_hop = std::static_pointer_cast<path::TransitHop>(
          _router.path_context().GetByUpstream(_router.pubkey(), PathID_t{to_usv(tx_id).data()}));

      if (auto exit_ep =
              _router.exitContext().FindEndpointForPath(PathID_t{to_usv(path_id).data()}))
      {
        if (CryptoManager::instance()->verify(exit_ep->PubKey().data(), to_usv(dict_data), sig))
        {
          (exit_ep->UpdateLocalPath(transit_hop->info.rxID))
              ? m.respond(UpdateExitMessage::sign_and_serialize_response(_router.identity(), tx_id))
              : m.respond(serialize_response({{"STATUS", UpdateExitMessage::UPDATE_FAILED}}), true);
        }
        // If we fail to verify the message, no-op
      }
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", UpdateExitMessage::EXCEPTION}}), true);
      return;
    }
  }

  void
  LinkManager::handle_update_exit_response(oxen::quic::message m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "UpdateExitMessage timed out!");
      return;
    }
    if (m.is_error)
    {
      // TODO: what to do here
    }

    try
    {
      std::string tx_id;
      ustring_view sig;

      oxenc::bt_list_consumer btlc{m.body()};
      auto dict_data = btlc.consume_dict_data();
      oxenc::bt_dict_consumer btdc{dict_data};

      sig = to_usv(btlc.consume_string_view());
      tx_id = btdc.require<std::string_view>("T");

      auto path_ptr = std::static_pointer_cast<path::Path>(
          _router.path_context().GetByDownstream(_router.pubkey(), PathID_t{to_usv(tx_id).data()}));

      if (CryptoManager::instance()->verify(_router.pubkey(), to_usv(dict_data), sig))
      {
        if (path_ptr->update_exit(std::stoul(tx_id)))
        {
          // TODO: talk to tom and Jason about how this stupid shit was a no-op originally
          // see Path::HandleUpdateExitVerifyMessage
        }
        else
        {}
      }
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      return;
    }
  }

  void
  LinkManager::handle_close_exit(oxen::quic::message m, const RouterID& from)
  {
    try
    {
      std::string_view tx_id;
      ustring_view sig;

      oxenc::bt_list_consumer btlc{m.body()};
      auto dict_data = btlc.consume_dict_data();
      oxenc::bt_dict_consumer btdc{dict_data};

      sig = to_usv(btlc.consume_string_view());
      tx_id = btdc.require<std::string_view>("T");

      auto transit_hop = std::static_pointer_cast<path::TransitHop>(
          _router.path_context().GetByUpstream(_router.pubkey(), PathID_t{to_usv(tx_id).data()}));

      const auto rx_id = transit_hop->info.rxID;

      if (auto exit_ep = router().exitContext().FindEndpointForPath(rx_id))
      {
        if (CryptoManager::instance()->verify(exit_ep->PubKey().data(), to_usv(dict_data), sig))
        {
          exit_ep->Close();
          m.respond(CloseExitMessage::sign_and_serialize_response(_router.identity(), tx_id));
        }
      }

      m.respond(serialize_response({{"STATUS", CloseExitMessage::UPDATE_FAILED}}), true);
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      m.respond(serialize_response({{"STATUS", CloseExitMessage::EXCEPTION}}), true);
      return;
    }
  }

  void
  LinkManager::handle_close_exit_response(oxen::quic::message m)
  {
    if (m.timed_out)
    {
      log::info(link_cat, "CloseExitMessage timed out!");
      return;
    }
    if (m.is_error)
    {
      // TODO: what to do here
    }

    try
    {
      std::string_view nonce, tx_id;
      ustring_view sig;

      oxenc::bt_list_consumer btlc{m.body()};
      auto dict_data = btlc.consume_dict_data();
      oxenc::bt_dict_consumer btdc{dict_data};

      sig = to_usv(btlc.consume_string_view());
      tx_id = btdc.require<std::string_view>("T");
      nonce = btdc.require<std::string_view>("Y");

      auto path_ptr = std::static_pointer_cast<path::Path>(
          _router.path_context().GetByDownstream(_router.pubkey(), PathID_t{to_usv(tx_id).data()}));

      if (path_ptr->SupportsAnyRoles(path::ePathRoleExit | path::ePathRoleSVC)
          and CryptoManager::instance()->verify(_router.pubkey(), to_usv(dict_data), sig))
        path_ptr->mark_exit_closed();
    }
    catch (const std::exception& e)
    {
      log::warning(link_cat, "Exception: {}", e.what());
      return;
    }
  }
}  // namespace llarp
