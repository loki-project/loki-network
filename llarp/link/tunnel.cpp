#include "tunnel.hpp"

#include <llarp/ev/libuv.hpp>
#include <llarp/service/endpoint.hpp>
#include <llarp/service/name.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/logging/buffer.hpp>
#include <llarp/util/str.hpp>

#include <limits>
#include <memory>
#include <stdexcept>
#include <type_traits>

namespace llarp::quic
{
    namespace
    {
        // Takes data from the tcp connection and pushes it down the quic tunnel
        void on_outgoing_data(uvw::DataEvent& event, uvw::TCPHandle& client)
        {
            auto stream = client.data<Stream>();
            assert(stream);
            std::string_view data{event.data.get(), event.length};
            auto peer = client.peer();
            LogTrace(peer.ip, ":", peer.port, " → lokinet ", buffer_printer{data});
            // Steal the buffer from the DataEvent's unique_ptr<char[]>:
            stream->append_buffer(reinterpret_cast<const std::byte*>(event.data.release()), event.length);
            if (stream->used() >= tunnel::PAUSE_SIZE)
            {
                LogDebug(
                    "quic tunnel is congested (have ",
                    stream->used(),
                    " bytes in flight); pausing local tcp connection reads");
                client.stop();
                stream->when_available([](Stream& s) {
                    auto client = s.data<uvw::TCPHandle>();
                    if (s.used() < tunnel::PAUSE_SIZE)
                    {
                        LogDebug("quic tunnel is no longer congested; resuming tcp connection reading");
                        client->read();
                        return true;
                    }
                    return false;
                });
            }
            else
            {
                LogDebug("Queued ", event.length, " bytes");
            }
        }

        // Received data from the quic tunnel and sends it to the TCP connection
        void on_incoming_data(Stream& stream, bstring_view bdata)
        {
            auto tcp = stream.data<uvw::TCPHandle>();
            if (!tcp)
                return;  // TCP connection is gone, which would have already sent a stream close, so
                         // just drop it.

            std::string_view data{reinterpret_cast<const char*>(bdata.data()), bdata.size()};
            auto peer = tcp->peer();
            LogTrace(peer.ip, ":", peer.port, " ← lokinet ", buffer_printer{data});

            if (data.empty())
                return;

            // Try first to write immediately from the existing buffer to avoid needing an
            // allocation and copy:
            auto written = tcp->tryWrite(const_cast<char*>(data.data()), data.size());
            if (written < (int)data.size())
            {
                data.remove_prefix(written);

                auto wdata = std::make_unique<char[]>(data.size());
                std::copy(data.begin(), data.end(), wdata.get());
                tcp->write(std::move(wdata), data.size());
            }
        }

        void close_tcp_pair(quic::Stream& st, std::optional<uint64_t> /*errcode*/)
        {
            if (auto tcp = st.data<uvw::TCPHandle>())
            {
                LogTrace("Closing TCP connection");
                tcp->close();
            }
        };
        // Creates a new tcp handle that forwards incoming data/errors/closes into appropriate
        // actions on the given quic stream.
        void install_stream_forwarding(uvw::TCPHandle& tcp, Stream& stream)
        {
            tcp.data(stream.shared_from_this());
            stream.weak_data(tcp.weak_from_this());

            tcp.clear();  // Clear any existing initial event handlers

            tcp.on<uvw::CloseEvent>([](auto&, uvw::TCPHandle& c) {
                // This fires sometime after we call `close()` to signal that the close is done.
                if (auto stream = c.data<Stream>())
                {
                    LogInfo("Local TCP connection closed, closing associated quic stream ", stream->id());
                    stream->close();
                    stream->data(nullptr);
                }
                c.data(nullptr);
            });
            tcp.on<uvw::EndEvent>([](auto&, uvw::TCPHandle& c) {
                // This fires on eof, most likely because the other side of the TCP connection
                // closed it.
                LogInfo("EOF on connection to ", c.peer().ip, ":", c.peer().port);
                c.close();
            });
            tcp.on<uvw::ErrorEvent>([](const uvw::ErrorEvent& e, uvw::TCPHandle& tcp) {
                LogError(
                    "ErrorEvent[",
                    e.name(),
                    ": ",
                    e.what(),
                    "] on connection with ",
                    tcp.peer().ip,
                    ":",
                    tcp.peer().port,
                    ", shutting down quic stream");
                if (auto stream = tcp.data<Stream>())
                {
                    stream->close(tunnel::ERROR_TCP);
                    stream->data(nullptr);
                    tcp.data(nullptr);
                }
                // tcp.closeReset();
            });
            tcp.on<uvw::DataEvent>(on_outgoing_data);
            stream.data_callback = on_incoming_data;
            stream.close_callback = close_tcp_pair;
        }
        // This initial data handler is responsible for pulling off the initial stream data that
        // comes back, confirming that the tunnel is opened on the other end.  Currently this is a
        // null byte (CONNECT_INIT) but in the future we might encode additional data here (and, if
        // that happens, we want this older implementation to fail).
        //
        // If the initial byte checks out we replace this handler with the regular stream handler
        // (and forward the rest of the data to it if we got more than just the single byte).
        void initial_client_data_handler(uvw::TCPHandle& client, Stream& stream, bstring_view bdata)
        {
            LogTrace("initial client handler; data: ", buffer_printer{bdata});
            if (bdata.empty())
                return;
            client.clear();  // Clear these initial event handlers: we either set up the proper
                             // ones, or close

            if (auto b0 = bdata[0]; b0 == tunnel::CONNECT_INIT)
            {
                // Set up callbacks, which replaces both of these initial callbacks
                client.read();  // Unfreeze (we stop() before putting into pending)
                install_stream_forwarding(client, stream);

                if (bdata.size() > 1)
                {
                    bdata.remove_prefix(1);
                    stream.data_callback(stream, std::move(bdata));
                }
                LogTrace("starting client reading");
            }
            else
            {
                LogWarn(
                    "Remote connection returned invalid initial byte (0x",
                    oxenc::to_hex(bdata.begin(), bdata.begin() + 1),
                    "); dropping connection");
                stream.close(tunnel::ERROR_BAD_INIT);
                client.close();
            }
            stream.io_ready();
        }

        // Initial close handler that gets replaced as soon as we receive a valid byte (in the above
        // handler).  If this gets called then it means the quic remote quic end closed before we
        // established the end-to-end tunnel (for example because the remote's tunnel connection
        // failed):
        void initial_client_close_handler(
            uvw::TCPHandle& client, Stream& /*stream*/, std::optional<uint64_t> error_code)
        {
            if (error_code && *error_code == tunnel::ERROR_CONNECT)
                LogDebug("Remote TCP connection failed, closing local connection");
            else
                LogWarn(
                    "Stream connection closed ",
                    error_code ? "with error " + std::to_string(*error_code) : "gracefully",
                    "; closing local TCP connection.");
            auto peer = client.peer();
            LogDebug("Closing connection to ", peer.ip, ":", peer.port);
            client.clear();
            // TOFIX: this logic
            //   if (error_code)
            // client.close();
            //   else
            client.close();
        }

    }  // namespace

    TunnelManager::TunnelManager(EndpointBase& se) : service_endpoint_{se}
    {
        // Cleanup callback to clear out closed tunnel connections
        service_endpoint_.Loop()->call_every(500ms, timer_keepalive_, [this] {
            LogTrace("Checking quic tunnels for finished connections");
            for (auto ctit = client_tunnels_.begin(); ctit != client_tunnels_.end();)
            {
                // Clear any accepted connections that have been closed:
                auto& [port, ct] = *ctit;
                for (auto it = ct.conns.begin(); it != ct.conns.end();)
                {
                    // TCP connections keep a shared_ptr to their quic::Stream while open and clear
                    // it when closed.  (We don't want to use `.active()` here because we do
                    // deliberately temporarily stop the TCP connection when the quic side gets
                    // congested.
                    if (not *it or not(*it)->data())
                    {
                        LogDebug("Cleanup up closed outgoing tunnel on quic:", port);
                        it = ct.conns.erase(it);
                    }
                    else
                        ++it;
                }

                // If there are not accepted connections left *and* we stopped listening for new
                // ones then destroy the whole thing.
                if (ct.conns.empty() and (not ct.tcp or not ct.tcp->active()))
                {
                    LogDebug("All sockets closed on quic:", port, ", destroying tunnel data");
                    ctit = client_tunnels_.erase(ctit);
                }
                else
                    ++ctit;
            }
            LogTrace("Done quic tunnel cleanup check");
        });
    }

    void TunnelManager::make_server()
    {
        // auto loop = get_loop();

        server_ = std::make_unique<Server>(service_endpoint_);
        server_->stream_open_callback = [this](Stream& stream, uint16_t port) -> bool {
            stream.close_callback = close_tcp_pair;

            auto& conn = stream.get_connection();
            auto remote = service_endpoint_.GetEndpointWithConvoTag(conn.path.remote);
            if (!remote)
            {
                LogWarn("Received new stream open from invalid/unknown convo tag, dropping stream");
                return false;
            }

            auto lokinet_addr = var::visit([](auto&& remote) { return remote.to_string(); }, *remote);
            auto tunnel_to = allow_connection(lokinet_addr, port);
            if (not tunnel_to)
                return false;
            LogInfo("quic stream from ", lokinet_addr, " to ", port, " tunnelling to ", *tunnel_to);

            auto tcp = get_loop()->resource<uvw::TCPHandle>();
            [[maybe_unused]] auto error_handler =
                tcp->once<uvw::ErrorEvent>([&stream, to = *tunnel_to](const uvw::ErrorEvent&, uvw::TCPHandle&) {
                    LogWarn("Failed to connect to ", to, ", shutting down quic stream");
                    stream.close(tunnel::ERROR_CONNECT);
                });

            // As soon as we connect to the local tcp tunnel port we fire a CONNECT_INIT down the
            // stream tunnel to let the other end know the connection was successful, then set up
            // regular stream handling to handle any other to/from data.
            tcp->once<uvw::ConnectEvent>(
                [streamw = stream.weak_from_this()](const uvw::ConnectEvent&, uvw::TCPHandle& tcp) {
                    auto peer = tcp.peer();
                    auto stream = streamw.lock();
                    if (!stream)
                    {
                        LogWarn(
                            "Connected to TCP ",
                            peer.ip,
                            ":",
                            peer.port,
                            " but quic stream has gone away; close/resetting local TCP connection");
                        tcp.close();
                        return;
                    }
                    LogDebug("Connected to ", peer.ip, ":", peer.port, " for quic ", stream->id());
                    // Set up the data stream forwarding (which also clears these initial handlers).
                    install_stream_forwarding(tcp, *stream);
                    assert(stream->used() == 0);

                    // Send the magic byte, and start reading from the tcp tunnel in the logic
                    // thread
                    stream->append_buffer(new std::byte[1]{tunnel::CONNECT_INIT}, 1);
                    tcp.read();
                });

            tcp->connect(*tunnel_to->operator const sockaddr*());

            return true;
        };
    }

    int TunnelManager::listen(ListenHandler handler)
    {
        if (!handler)
            throw std::logic_error{"Cannot call listen() with a null handler"};
        assert(service_endpoint_.Loop()->inEventLoop());
        if (not server_)
            make_server();

        int id = next_handler_id_++;
        incoming_handlers_.emplace_hint(incoming_handlers_.end(), id, std::move(handler));
        return id;
    }

    int TunnelManager::listen(SockAddr addr)
    {
        return listen([addr](std::string_view, uint16_t p) -> std::optional<SockAddr> {
            LogInfo("try accepting ", addr.getPort());
            if (p == addr.getPort())
                return addr;
            return std::nullopt;
        });
    }

    void TunnelManager::forget(int id)
    {
        incoming_handlers_.erase(id);
    }

    std::optional<SockAddr> TunnelManager::allow_connection(std::string_view lokinet_addr, uint16_t port)
    {
        for (auto& [id, handler] : incoming_handlers_)
        {
            try
            {
                if (auto addr = handler(lokinet_addr, port))
                    return addr;
            }
            catch (const std::exception& e)
            {
                LogWarn(
                    "Incoming quic connection from ",
                    lokinet_addr,
                    " to ",
                    port,
                    " denied via exception (",
                    e.what(),
                    ")");
                return std::nullopt;
            }
        }
        LogWarn("Incoming quic connection from ", lokinet_addr, " to ", port, " declined by all handlers");
        return std::nullopt;
    }

    std::shared_ptr<uvw::Loop> TunnelManager::get_loop()
    {
        if (auto loop = service_endpoint_.Loop()->MaybeGetUVWLoop())
            return loop;
        throw std::logic_error{"TunnelManager requires a libuv-based event loop"};
    }

    // Finds the first unused key in `map`, starting at `start` and wrapping back to 0 if we hit the
    // end.  Requires an unsigned int type for the key.  Requires nullopt if the map is completely
    // full, otherwise returns the free key.
    template <typename K, typename V, typename = std::enable_if_t<std::is_integral_v<K> && std::is_unsigned_v<K>>>
    static std::optional<K> find_unused_key(std::map<K, V>& map, K start)
    {
        if (map.size() == std::numeric_limits<K>::max())
            return std::nullopt;  // The map is completely full
        [[maybe_unused]] bool from_zero = (start == K{0});

        // Start at the first key >= start, then walk 1-by-1 (incrementing start) until we find a
        // strictly > key, which means we've found a hole we can use
        auto it = map.lower_bound(start);
        if (it == map.end())
            return start;

        for (; it != map.end(); ++it, ++start)
            if (it->first != start)
                return start;
        if (start != 0)  // `start` didn't wrap which means we found an empty slot
            return start;
        assert(!from_zero);  // There *must* be a free slot somewhere in [0, max] (otherwise the map
                             // would be completely full and we'd have returned nullopt).
        return find_unused_key(map, K{0});
    }

    // Wrap common tasks and cleanup that we need to do from multiple places while establishing a
    // tunnel
    bool TunnelManager::continue_connecting(
        uint16_t pseudo_port, bool step_success, std::string_view step_name, std::string_view addr)
    {
        assert(service_endpoint_.Loop()->inEventLoop());
        auto it = client_tunnels_.find(pseudo_port);
        if (it == client_tunnels_.end())
        {
            LogDebug("QUIC tunnel to ", addr, " closed before ", step_name, " finished");
            return false;
        }
        if (!step_success)
        {
            LogWarn("QUIC tunnel to ", addr, " failed during ", step_name, "; aborting tunnel");
            it->second.tcp->close();
            if (it->second.open_cb)
                it->second.open_cb(false);
            client_tunnels_.erase(it);
        }
        return step_success;
    }

    std::pair<SockAddr, uint16_t> TunnelManager::open(
        std::string_view remote_address, uint16_t port, OpenCallback on_open, SockAddr bind_addr)
    {
        std::string remote_addr = lowercase_ascii_string(std::string{remote_address});

        std::pair<SockAddr, uint16_t> result;
        auto& [saddr, pport] = result;

        auto maybe_remote = service::ParseAddress(remote_addr);
        if (!maybe_remote)
        {
            if (not service::NameIsValid(remote_addr))
                throw std::invalid_argument{"Invalid remote lokinet name/address"};
            // Otherwise it's a valid ONS name, so we'll initiate an ONS lookup below
        }

        // Open the TCP tunnel right away; it will just block new incoming connections until the
        // quic connection is established, but this still allows the caller to connect right away
        // and queue an initial request (rather than having to wait via a callback before
        // connecting).  It also makes sure we can actually listen on the given address before we go
        // ahead with establishing the quic connection.
        auto tcp_tunnel = get_loop()->resource<uvw::TCPHandle>();
        const char* failed = nullptr;
        auto err_handler = tcp_tunnel->once<uvw::ErrorEvent>([&failed](auto& evt, auto&) { failed = evt.what(); });
        tcp_tunnel->bind(*bind_addr.operator const sockaddr*());
        tcp_tunnel->on<uvw::ListenEvent>([this](const uvw::ListenEvent&, uvw::TCPHandle& tcp_tunnel) {
            auto client = tcp_tunnel.loop().resource<uvw::TCPHandle>();
            tcp_tunnel.accept(*client);
            // Freeze the connection (after accepting) because we may need to stall it until a
            // stream becomes available; flush_pending_incoming will unfreeze it.
            client->stop();
            auto pport = tcp_tunnel.data<uint16_t>();
            if (pport)
            {
                if (auto it = client_tunnels_.find(*pport); it != client_tunnels_.end())
                {
                    it->second.pending_incoming.emplace(std::move(client));
                    flush_pending_incoming(it->second);
                    return;
                }
                tcp_tunnel.data(nullptr);
            }
            client->close();
        });
        tcp_tunnel->listen();
        tcp_tunnel->erase(err_handler);

        if (failed)
        {
            tcp_tunnel->close();
            throw std::runtime_error{
                fmt::format("Failed to bind/listen local TCP tunnel socket on {}: {}", bind_addr, failed)};
        }

        auto bound = tcp_tunnel->sock();
        saddr = SockAddr{bound.ip, huint16_t{static_cast<uint16_t>(bound.port)}};

        // Find the first unused psuedo-port value starting from next_pseudo_port_.
        if (auto p = find_unused_key(client_tunnels_, next_pseudo_port_))
            pport = *p;
        else
            throw std::runtime_error{"Unable to open an outgoing quic connection: too many existing connections"};
        (next_pseudo_port_ = pport)++;

        LogInfo("Bound TCP tunnel ", saddr, " for quic client :", pport);

        // We are emplacing into client_tunnels_ here: beyond this point we must not throw until we
        // return (or if we do, make sure we remove this row from client_tunnels_ first).
        assert(client_tunnels_.count(pport) == 0);
        auto& ct = client_tunnels_[pport];
        ct.open_cb = std::move(on_open);
        ct.tcp = std::move(tcp_tunnel);
        // We use this pport shared_ptr value on the listening tcp socket both to hand to pport into
        // the accept handler, and to let the accept handler know that `this` is still safe to use.
        ct.tcp->data(std::make_shared<uint16_t>(pport));

        auto after_path = [this, port, pport = pport, remote_addr](auto maybe_convo) {
            if (not continue_connecting(pport, (bool)maybe_convo, "path build", remote_addr))
                return;
            SockAddr dest{maybe_convo->ToV6()};
            dest.setPort(port);
            make_client(dest, *client_tunnels_.find(pport));
        };

        if (!maybe_remote)
        {
            // We were given an ONS address, so it's a two-step process: first we resolve the ONS
            // name, then we have to build a path to that address.
            service_endpoint_.LookupNameAsync(
                remote_addr,
                [this, after_path = std::move(after_path), pport = pport, remote_addr = std::move(remote_addr)](
                    auto maybe_remote) {
                    if (not continue_connecting(pport, (bool)maybe_remote, "endpoint ONS lookup", remote_addr))
                        return;
                    service_endpoint_.MarkAddressOutbound(*maybe_remote);
                    service_endpoint_.EnsurePathTo(*maybe_remote, after_path, open_timeout);
                });
            return result;
        }

        auto& remote = *maybe_remote;

        // See if we have an existing convo tag we can use to start things immediately
        if (auto maybe_convo = service_endpoint_.GetBestConvoTagFor(remote))
            after_path(maybe_convo);
        else
        {
            service_endpoint_.MarkAddressOutbound(remote);
            service_endpoint_.EnsurePathTo(remote, after_path, open_timeout);
        }

        return result;
    }

    void TunnelManager::close(int id)
    {
        if (auto it = client_tunnels_.find(id); it != client_tunnels_.end())
        {
            it->second.tcp->close();
            it->second.tcp->data(nullptr);
            it->second.tcp.reset();
        }
    }

    TunnelManager::ClientTunnel::~ClientTunnel()
    {
        if (tcp)
        {
            tcp->close();
            tcp->data(nullptr);
            tcp.reset();
        }
        for (auto& conn : conns)
            conn->close();
        conns.clear();

        while (not pending_incoming.empty())
        {
            if (auto tcp = pending_incoming.front().lock())
            {
                tcp->clear();
                tcp->close();
            }
            pending_incoming.pop();
        }
    }

    void TunnelManager::make_client(const SockAddr& remote, std::pair<const uint16_t, ClientTunnel>& row)
    {
        assert(remote.getPort() > 0);
        auto& [pport, tunnel] = row;
        assert(not tunnel.client);
        tunnel.client = std::make_unique<Client>(service_endpoint_, remote, pport);
        auto conn = tunnel.client->get_connection();

        conn->on_stream_available = [this, id = row.first](Connection&) {
            LogDebug("QUIC connection :", id, " established; streams now available");
            if (auto it = client_tunnels_.find(id); it != client_tunnels_.end())
                flush_pending_incoming(it->second);
        };
    }

    void TunnelManager::flush_pending_incoming(ClientTunnel& ct)
    {
        if (!ct.client)
            return;  // Happens if we're still waiting for a path to build
        if (not ct.client->get_connection())
            return;
        auto& conn = *ct.client->get_connection();
        int available = conn.get_streams_available();
        while (available > 0 and not ct.pending_incoming.empty())
        {
            auto tcp_client = ct.pending_incoming.front().lock();
            ct.pending_incoming.pop();
            if (not tcp_client)
                continue;

            try
            {
                auto str = conn.open_stream(
                    [tcp_client](auto&&... args) {
                        initial_client_data_handler(*tcp_client, std::forward<decltype(args)>(args)...);
                    },
                    [tcp_client](auto&&... args) {
                        initial_client_close_handler(*tcp_client, std::forward<decltype(args)>(args)...);
                    });
                available--;
            }
            catch (const std::exception& e)
            {
                LogWarn("Opening quic stream failed: ", e.what());
                tcp_client->close();
            }

            LogTrace("Set up new stream");
            conn.io_ready();
        }
    }

    void TunnelManager::receive_packet(const service::ConvoTag& tag, const llarp_buffer_t& buf)
    {
        if (buf.sz <= 4)
        {
            LogWarn("invalid quic packet: packet size (", buf.sz, ") too small");
            return;
        }
        auto type = static_cast<std::byte>(buf.base[0]);
        nuint16_t pseudo_port_n;
        std::memcpy(&pseudo_port_n.n, &buf.base[1], 2);
        uint16_t pseudo_port = ToHost(pseudo_port_n).h;
        auto ecn = static_cast<uint8_t>(buf.base[3]);
        bstring_view data{reinterpret_cast<const std::byte*>(&buf.base[4]), buf.sz - 4};

        SockAddr remote{tag.ToV6()};
        quic::Endpoint* ep = nullptr;
        if (type == CLIENT_TO_SERVER)
        {
            LogTrace("packet is client-to-server from client pport ", pseudo_port);
            // Client-to-server: the header port is the return port
            remote.setPort(pseudo_port);
            if (!server_)
            {
                LogWarn("Dropping incoming quic packet to server: no listeners");
                return;
            }
            ep = server_.get();
        }
        else if (type == SERVER_TO_CLIENT)
        {
            LogTrace("packet is server-to-client to client pport ", pseudo_port);
            // Server-to-client: the header port tells us which client tunnel this is going to
            if (auto it = client_tunnels_.find(pseudo_port); it != client_tunnels_.end())
                ep = it->second.client.get();

            if (not ep)
            {
                LogWarn("Incoming quic packet to invalid/closed client; dropping");
                return;
            }

            // The server doesn't send back the port because we already know it 1-to-1 from our
            // outgoing connection.
            if (auto conn = static_cast<quic::Client&>(*ep).get_connection())
            {
                remote.setPort(conn->path.remote.port());
                LogTrace("remote port is ", remote.getPort());
            }
            else
            {
                LogWarn("Incoming quic to a quic::Client without an active quic::Connection; dropping");
                return;
            }
        }
        else
        {
            LogWarn("Invalid incoming quic packet type ", type, "; dropping packet");
            return;
        }
        ep->receive_packet(remote, ecn, data);
    }
}  // namespace llarp::quic
