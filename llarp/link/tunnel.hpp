#pragma once

#include <llarp/net/sock_addr.hpp>
#include <llarp/service/tag.hpp>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <queue>
#include <string>
#include <string_view>
#include <unordered_set>

// #include <uvw/tcp.h>

namespace llarp
{
    class EndpointBase;
}

namespace llarp::link
{
    // struct Endpoint;

    using namespace std::chrono_literals;

    namespace tunnel
    {
        // The server sends back a 0x00 to signal that the remote TCP connection was established and
        // that it is now accepting stream data; the client is not allowed to send any other data
        // down the stream until this comes back (any data sent down the stream before then is
        // discarded.)
        inline constexpr std::byte CONNECT_INIT{0x00};
        // QUIC application error codes we sent on failures:
        // Failure to establish an initial connection:
        inline constexpr uint64_t ERROR_CONNECT{0x5471907};
        // Error if we receive something other than CONNECT_INIT as the initial stream data from the
        // server
        inline constexpr uint64_t ERROR_BAD_INIT{0x5471908};
        // Close error code sent if we get an error on the TCP socket (other than an initial connect
        // failure)
        inline constexpr uint64_t ERROR_TCP{0x5471909};

        // We pause reading from the local TCP socket if we have more than this amount of
        // outstanding unacked data in the quic tunnel, then resume once it drops below this.
        inline constexpr size_t PAUSE_SIZE = 64 * 1024;
    }  // namespace tunnel

    /// Manager class for incoming and outgoing QUIC tunnels.
    class TunnelManager
    {
      public:
        using ListenHandler = std::function<std::optional<oxen::quic::Address>(
            std::string_view lokinet_addr,  // The remote's full lokinet address
            uint16_t port                   // The requested port the tunnel wants to reach
            )>;

        // Timeout for the next `open()`.  Note that when `open()` is given a ONS name to resolve
        // this includes the resolution time.
        std::chrono::milliseconds open_timeout = 4s;

        TunnelManager(EndpointBase& endpoint);

        /// Adds an incoming listener callback.  When a new incoming quic connection is initiated to
        /// us by some remote we invoke these callback(s) in order of registration.  Each one has
        /// three options:
        /// - return a concrete llarp::SockAddr giving the TCP address/port to which we should
        /// connect new incoming streams over the connection.
        /// - returns std::nullopt to decline handling the connection (we will try the next listen
        /// handler, in order of registration).
        /// - throws an exception (derived from std::exception) in which case we refuse the
        /// connection without trying any additional handlers.
        ///
        /// If `listen()` is not called at all then new incoming connections will be immediately
        /// dropped.
        ///
        /// For plain-C wrappers around this see [FIXME].
        int listen(ListenHandler handler);

        /// Simple wrapper around `listen(...)` that adds a handler that accepts all incoming
        /// connections trying to tunnel to port `port` and maps them to `localhost:port`.
        int listen(oxen::quic::Address port);

        /// Removes an incoming connection handler; takes the ID returned by `listen()`.
        void forget(int id);

        /// Called when open succeeds or times out.
        using OpenCallback = std::function<void(bool success)>;

        /// Opens a quic tunnel to some remote lokinet address.  (Should only be called from the
        /// event loop thread.)
        ///
        /// \param remote_addr is the lokinet address or ONS name (e.g. `azfojblahblahblah.loki` or
        /// `blocks.loki`) that the tunnel should connect to.
        /// \param port is the tunneled port on the remote that the client wants to reach.  (This is
        /// *not* the quic pseudo-port, which is always 0).
        /// \param callback callback invoked when the quic connection has been established, or has
        /// timed out. \param bind_addr is the bind address and port that we should use for the
        /// localhost TCP connection.  Use port 0 to let the OS choose a random high port.  Defaults
        /// to `127.0.0.1:0`.
        ///
        /// This call immediately opens the local TCP socket, and initiates the lokinet connection
        /// and QUIC tunnel to the remote.  If the connection fails, the TCP socket will be closed.
        /// Note, however, that this TCP socket will block until the underlying quic connection is
        /// established.
        ///
        /// Each connection to the local TCP socket establishes a new stream over the QUIC
        /// connection.
        ///
        /// \return a pair:
        /// - SockAddr containing the just-opened localhost socket that tunnels to the remote.  This
        /// is typically the same IP as `bind_addr`, with the port filled in (if bind_addr had a 0
        /// port). Note that, while you can connect to this socket immediately, it will block until
        /// the actual connection and streams are established (and will be closed if they fail).
        /// - unique integer that can be passed to close() to stop listening for new connections.
        /// This also serves as a unique internal "pseudo-port" number to route returned quic
        /// packets to the right connection.
        ///
        /// TODO: add a callback to invoke when QUIC connection succeeds or fails.
        /// TODO: add a plain C wrapper around this
        std::pair<oxen::quic::Address, uint16_t> open(
            std::string_view remote_addr,
            uint16_t port,
            OpenCallback on_open = {},
            oxen::quic::Address bind_addr = {"127.0.0.1", 0});

        /// Start closing an outgoing tunnel; takes the ID returned by `open()`.  Note that an
        /// existing established tunneled connections will not be forcibly closed; this simply stops
        /// accepting new tunnel connections.
        void close(int id);

        /// Called from tun code to deliver a quic packet.
        ///
        /// \param dest - the convotag for which the packet arrived
        /// \param buf - the raw arriving packet
        ///
        void receive_packet(const service::SessionTag& tag, const llarp_buffer_t& buf);

        /// return true if we have any listeners added
        inline bool hasListeners() const
        {
            return not incoming_handlers_.empty();
        }

      private:
        EndpointBase& service_endpoint_;

        struct ClientTunnel
        {
            // quic endpoint
            // std::unique_ptr<Endpoint> client;
            // Callback to invoke on quic connection established (true argument) or failed (false
            // arg)
            OpenCallback open_cb;
            // TCP listening socket
            // std::shared_ptr<uvw::TCPHandle> tcp;
            // // Accepted TCP connections
            // std::unordered_set<std::shared_ptr<uvw::TCPHandle>> conns;
            // // Queue of incoming connections that are waiting for a stream to become available
            // (either
            // // because we are still handshaking, or we reached the stream limit).
            // std::queue<std::weak_ptr<uvw::TCPHandle>> pending_incoming;

            ~ClientTunnel()
            {
                // if (tcp)
                // {
                //   tcp->close();
                //   tcp->data(nullptr);
                //   tcp.reset();
                // }
                // for (auto& conn : conns)
                //   conn->close();
                // conns.clear();

                // while (not pending_incoming.empty())
                // {
                //   if (auto tcp = pending_incoming.front().lock())
                //   {
                //     tcp->clear();
                //     tcp->close();
                //   }
                //   pending_incoming.pop();
                // }
            }
        };

        // pseudo-port -> Client instance (the "port" is used to route incoming quic packets to the
        // right quic endpoint); pseudo-ports start at 1.
        std::map<uint16_t, ClientTunnel> client_tunnels_;

        uint16_t next_pseudo_port_ = 0;
        // bool pport_wrapped_ = false;

        bool continue_connecting(
            uint16_t pseudo_port, bool step_success, std::string_view step_name, std::string_view addr);

        void make_client(const oxen::quic::Address& remote, std::pair<const uint16_t, ClientTunnel>& row);

        void flush_pending_incoming(ClientTunnel& ct);

        // Server instance; this listens on pseudo-port 0 (if it listens).  This is automatically
        // instantiated the first time `listen()` is called; if not instantiated we simply drop any
        // inbound client-to-server quic packets.
        // std::unique_ptr<Server> server_;

        void make_server();

        // Called when a new during connection handshaking once we have the established transport
        // parameters (which include the port) if this is an incoming connection (and this endpoint
        // is a server).  This checks handlers to see whether the stream is allowed and, if so,
        // returns a SockAddr containing the IP/port the tunnel should map to.  Returns nullopt if
        // the connection should be rejected.
        std::optional<oxen::quic::Address> allow_connection(std::string_view lokinet_addr, uint16_t port);

        // Incoming stream handlers
        std::map<int, ListenHandler> incoming_handlers_;
        int next_handler_id_ = 1;

        // std::shared_ptr<uvw::Loop>
        // get_loop();

        // Cleanup member
        std::shared_ptr<int> timer_keepalive_ = std::make_shared<int>(0);
    };

}  // namespace llarp::link
