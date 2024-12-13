#include "endpoint.hpp"
#include "client.hpp"
#include "server.hpp"
#include "uvw/async.h"
#include <llarp/crypto/crypto.hpp>
#include <llarp/util/logging/buffer.hpp>
#include <llarp/service/endpoint.hpp>
#include <llarp/ev/libuv.hpp>

#include <iostream>
#include <random>
#include <variant>

#include <uvw/timer.h>
#include <oxenc/variant.h>

extern "C"
{
#include <sodium/crypto_generichash.h>
#include <sodium/randombytes.h>
}

namespace llarp::quic
{
  Endpoint::Endpoint(EndpointBase& ep) : service_endpoint{ep}
  {
    randombytes_buf(static_secret.data(), static_secret.size());

    // Set up a callback every 250ms to clean up stale sockets, etc.
    expiry_timer = get_loop()->resource<uvw::TimerHandle>();
    expiry_timer->on<uvw::TimerEvent>([this](const auto&, auto&) { check_timeouts(); });
    expiry_timer->start(250ms, 250ms);

    LogDebug("Created QUIC endpoint");
  }

  Endpoint::~Endpoint()
  {
    if (expiry_timer)
      expiry_timer->close();
  }

  std::shared_ptr<uvw::Loop>
  Endpoint::get_loop()
  {
    auto loop = service_endpoint.Loop()->MaybeGetUVWLoop();
    assert(loop);  // This object should never have been constructed if we aren't using uvw
    return loop;
  }

  void
  Endpoint::receive_packet(const SockAddr& src, uint8_t ecn, bstring_view data)
  {
    // ngtcp2 wants a local address but we don't necessarily have something so just set it to
    // IPv4 or IPv6 "unspecified" address (0.0.0.0 or ::)
    SockAddr local = src.isIPv6() ? SockAddr{in6addr_any} : SockAddr{nuint32_t{INADDR_ANY}};

    Packet pkt{Path{local, src}, data, ngtcp2_pkt_info{.ecn = ecn}};

    LogTrace("[", pkt.path, ",ecn=", pkt.info.ecn, "]: received ", data.size(), " bytes");

    handle_packet(pkt);

    LogTrace("Done handling packet");
  }

  void
  Endpoint::handle_packet(const Packet& p)
  {
    LogTrace("Handling incoming quic packet: ", buffer_printer{p.data});
    auto maybe_dcid = handle_packet_init(p);
    if (!maybe_dcid)
      return;
    auto& dcid = *maybe_dcid;

    // See if we have an existing connection already established for it
    LogTrace("Incoming connection id ", dcid);
    auto [connptr, alias] = get_conn(dcid);
    if (!connptr)
    {
      if (alias)
      {
        LogDebug("Incoming packet QUIC CID is an expired alias; dropping");
        return;
      }
      connptr = accept_initial_connection(p);
      if (!connptr)
        return;
    }
    if (alias)
      LogTrace("CID is alias for primary CID ", connptr->base_cid);
    else
      LogTrace("CID is primary CID");

    handle_conn_packet(*connptr, p);
  }

  std::optional<ConnectionID>
  Endpoint::handle_packet_init(const Packet& p)
  {
    version_info vi;
    auto rv = ngtcp2_pkt_decode_version_cid(
        &vi.version,
        &vi.dcid,
        &vi.dcid_len,
        &vi.scid,
        &vi.scid_len,
        u8data(p.data),
        p.data.size(),
        NGTCP2_MAX_CIDLEN);
    if (rv == 1)
    {  // 1 means Version Negotiation should be sent and otherwise the packet should be ignored
      send_version_negotiation(vi, p.path.remote);
      return std::nullopt;
    }
    if (rv != 0)
    {
      LogWarn("QUIC packet header decode failed: ", ngtcp2_strerror(rv));
      return std::nullopt;
    }

    if (vi.dcid_len > ConnectionID::max_size())
    {
      LogWarn("Internal error: destination ID is longer than should be allowed");
      return std::nullopt;
    }

    return std::make_optional<ConnectionID>(vi.dcid, vi.dcid_len);
  }
  void
  Endpoint::handle_conn_packet(Connection& conn, const Packet& p)
  {
    if (ngtcp2_conn_is_in_closing_period(conn))
    {
      LogDebug("Connection is in closing period, dropping");
      close_connection(conn);
      return;
    }
    if (conn.draining)
    {
      LogDebug("Connection is draining, dropping");
      // "draining" state means we received a connection close and we're keeping the
      // connection alive just to catch (and discard) straggling packets that arrive
      // out of order w.r.t to connection close.
      return;
    }

    if (auto result = read_packet(p, conn); !result)
    {
      LogWarn("Read packet failed! ", ngtcp2_strerror(result.error_code));
    }

    // FIXME - reset idle timer?
    LogTrace("Done with incoming packet");
  }

  io_result
  Endpoint::read_packet(const Packet& p, Connection& conn)
  {
    LogTrace("Reading packet from ", p.path);
    auto rv =
        ngtcp2_conn_read_pkt(conn, p.path, &p.info, u8data(p.data), p.data.size(), get_timestamp());

    if (rv == 0)
      conn.io_ready();
    else
      LogWarn("read pkt error: ", ngtcp2_strerror(rv));

    if (rv == NGTCP2_ERR_DRAINING)
      start_draining(conn);
    else if (rv == NGTCP2_ERR_DROP_CONN)
      delete_conn(conn.base_cid);

    return {rv};
  }

  io_result
  Endpoint::send_packet(const Address& to, bstring_view data, uint8_t ecn)
  {
    assert(service_endpoint.Loop()->inEventLoop());

    size_t header_size = write_packet_header(to.port(), ecn);
    size_t outgoing_len = header_size + data.size();
    assert(outgoing_len <= buf_.size());
    std::memcpy(&buf_[header_size], data.data(), data.size());
    bstring_view outgoing{buf_.data(), outgoing_len};

    if (service_endpoint.SendToOrQueue(
            to, llarp_buffer_t{outgoing.data(), outgoing.size()}, service::ProtocolType::QUIC))
    {
      LogTrace("[", to, "]: sent ", buffer_printer{outgoing});
    }
    else
    {
      LogDebug("Failed to send to quic endpoint ", to, "; was sending ", outgoing.size(), "B");
    }
    return {};
  }

  void
  Endpoint::send_version_negotiation(const version_info& vi, const Address& source)
  {
    std::array<std::byte, Endpoint::max_pkt_size_v4> buf;
    std::array<uint32_t, NGTCP2_PROTO_VER_MAX - NGTCP2_PROTO_VER_MIN + 2> versions;
    std::iota(versions.begin() + 1, versions.end(), NGTCP2_PROTO_VER_MIN);
    // we're supposed to send some 0x?a?a?a?a version to trigger version negotiation
    versions[0] = 0x1a2a3a4au;

    CSRNG rng{};
    auto nwrote = ngtcp2_pkt_write_version_negotiation(
        u8data(buf),
        buf.size(),
        static_cast<uint8_t>(std::uniform_int_distribution<unsigned short>{0, 255}(rng)),
        vi.dcid,
        vi.dcid_len,
        vi.scid,
        vi.scid_len,
        versions.data(),
        versions.size());
    if (nwrote < 0)
      LogWarn("Failed to construct version negotiation packet: ", ngtcp2_strerror(nwrote));
    if (nwrote <= 0)
      return;

    send_packet(source, bstring_view{buf.data(), static_cast<size_t>(nwrote)}, 0);
  }

  void
  Endpoint::close_connection(
      Connection& conn, uint64_t code, bool application, std::string_view close_reason)
  {
    LogDebug("Closing connection ", conn.base_cid);
    if (!conn.closing)
    {
      conn.conn_buffer.resize(max_pkt_size_v4);
      Path path;
      ngtcp2_pkt_info pi;

      auto write_close_func = application ? ngtcp2_conn_write_application_close_versioned
                                          : ngtcp2_conn_write_connection_close_versioned;

      auto written = write_close_func(
          conn,
          path,
          NGTCP2_PKT_INFO_VERSION,
          &pi,
          u8data(conn.conn_buffer),
          conn.conn_buffer.size(),
          code,
          reinterpret_cast<const uint8_t*>(close_reason.data()),
          close_reason.size(),
          get_timestamp());
      if (written <= 0)
      {
        LogWarn(
            "Failed to write connection close packet: ",
            written < 0 ? ngtcp2_strerror(written) : "unknown error: closing is 0 bytes??");
        return;
      }
      assert(written <= (long)conn.conn_buffer.size());
      conn.conn_buffer.resize(written);
      conn.closing = true;

      conn.path = path;
    }
    assert(conn.closing && !conn.conn_buffer.empty());

    if (auto sent = send_packet(conn.path.remote, conn.conn_buffer, 0); not sent)
    {
      LogWarn(
          "Failed to send packet: ",
          strerror(sent.error_code),
          "; removing connection ",
          conn.base_cid);
      delete_conn(conn.base_cid);
      return;
    }
  }

  /// Puts a connection into draining mode (i.e. after getting a connection close).  This will
  /// keep the connection registered for the recommended 3*Probe Timeout, during which we drop
  /// packets that use the connection id and after which we will forget about it.
  void
  Endpoint::start_draining(Connection& conn)
  {
    if (conn.draining)
      return;
    LogDebug("Putting ", conn.base_cid, " into draining mode");
    conn.draining = true;
    // Recommended draining time is 3*Probe Timeout
    draining.emplace(conn.base_cid, get_time() + ngtcp2_conn_get_pto(conn) * 3 * 1ns);
  }

  void
  Endpoint::check_timeouts()
  {
    auto now = get_time();
    uint64_t now_ts = get_timestamp(now);

    // Destroy any connections that are finished draining
    bool cleanup = false;
    while (!draining.empty() && draining.front().second < now)
    {
      if (auto it = conns.find(draining.front().first); it != conns.end())
      {
        if (std::holds_alternative<primary_conn_ptr>(it->second))
          cleanup = true;
        LogDebug("Deleting connection ", it->first);
        conns.erase(it);
      }
      draining.pop();
    }
    if (cleanup)
      clean_alias_conns();

    for (auto it = conns.begin(); it != conns.end(); ++it)
    {
      if (auto* conn_ptr = std::get_if<primary_conn_ptr>(&it->second))
      {
        Connection& conn = **conn_ptr;
        auto exp = ngtcp2_conn_get_idle_expiry(conn);
        if (exp >= now_ts || conn.draining)
          continue;
        start_draining(conn);
      }
    }
  }

  std::pair<std::shared_ptr<Connection>, bool>
  Endpoint::get_conn(const ConnectionID& cid)
  {
    if (auto it = conns.find(cid); it != conns.end())
    {
      if (auto* wptr = std::get_if<alias_conn_ptr>(&it->second))
        return {wptr->lock(), true};
      return {var::get<primary_conn_ptr>(it->second), false};
    }
    return {nullptr, false};
  }

  bool
  Endpoint::delete_conn(const ConnectionID& cid)
  {
    auto it = conns.find(cid);
    if (it == conns.end())
    {
      LogDebug("Cannot delete connection ", cid, ": cid not found");
      return false;
    }

    bool primary = std::holds_alternative<primary_conn_ptr>(it->second);
    LogDebug("Deleting ", primary ? "primary" : "alias", " connection ", cid);
    conns.erase(it);
    if (primary)
      clean_alias_conns();
    return true;
  }

  void
  Endpoint::clean_alias_conns()
  {
    for (auto it = conns.begin(); it != conns.end();)
    {
      if (auto* conn_wptr = std::get_if<alias_conn_ptr>(&it->second);
          conn_wptr && conn_wptr->expired())
        it = conns.erase(it);
      else
        ++it;
    }
  }

  ConnectionID
  Endpoint::add_connection_id(Connection& conn, size_t cid_length)
  {
    ConnectionID cid;
    for (bool inserted = false; !inserted;)
    {
      cid = ConnectionID::random(cid_length);
      inserted = conns.emplace(cid, conn.weak_from_this()).second;
    }
    LogDebug("Created cid ", cid, " alias for ", conn.base_cid);
    return cid;
  }

  void
  Endpoint::make_stateless_reset_token(const ConnectionID& cid, unsigned char* dest)
  {
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, NGTCP2_STATELESS_RESET_TOKENLEN);
    crypto_generichash_update(&state, u8data(static_secret), static_secret.size());
    crypto_generichash_update(&state, cid.data, cid.datalen);
    crypto_generichash_final(&state, dest, NGTCP2_STATELESS_RESET_TOKENLEN);
  }

}  // namespace llarp::quic
