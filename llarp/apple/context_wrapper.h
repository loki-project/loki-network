#pragma once

// C-linkage wrappers for interacting with a lokinet context, so that we can call them from Swift
// code (which currently doesn't support C++ interoperability at all).

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/socket.h>
#include <unistd.h>
#include <uv.h>

    // Port (on localhost) for our DNS trampoline for bouncing DNS requests through the exit route
    // when in exit mode.
    extern const uint16_t dns_trampoline_port;

    /// C callback function for us to invoke when we need to write a packet
    typedef void (*packet_writer_callback)(int af, const void* data, size_t size, void* ctx);

    /// C callback function to invoke once we are ready to start receiving packets
    typedef void (*start_reading_callback)(void* ctx);

    /// C callback that bridges things into NSLog
    typedef void (*ns_logger_callback)(const char* msg);

    /// C callbacks to add/remove specific and default routes to the tunnel
    typedef void (*llarp_route_ipv4_callback)(const char* addr, const char* netmask, void* ctx);
    typedef void (*llarp_route_ipv6_callback)(const char* addr, int prefix, void* ctx);
    typedef void (*llarp_default_route_callback)(void* ctx);
    typedef struct llarp_route_callbacks
    {
        /// Callback invoked to set up an IPv4 range that should be routed through the tunnel
        /// interface.  Called with the address and netmask.
        llarp_route_ipv4_callback add_ipv4_route;

        /// Callback invoked to set the tunnel as the default IPv4 route.
        llarp_default_route_callback add_ipv4_default_route;

        /// Callback invoked to remove a specific range from the tunnel IPv4 routes.  Called with
        /// the address and netmask.
        llarp_route_ipv4_callback del_ipv4_route;

        /// Callback invoked to set up an IPv6 range that should be routed through the tunnel
        /// interface.  Called with the address and netmask.
        llarp_route_ipv6_callback add_ipv6_route;

        /// Callback invoked to remove a specific range from the tunnel IPv6 routes.  Called with
        /// the address and netmask.
        llarp_route_ipv6_callback del_ipv6_route;

        /// Callback invoked to set the tunnel as the default IPv4/IPv6 route.
        llarp_default_route_callback add_default_route;

        /// Callback invoked to remove the tunnel as the default IPv4/IPv6 route.
        llarp_default_route_callback del_default_route;
    } llarp_route_callbacks;

    /// Pack of crap to be passed into llarp_apple_init to initialize
    typedef struct llarp_apple_config
    {
        /// lokinet configuration directory, expected to be the application-specific "home"
        /// directory, which is where state files are stored and the lokinet.ini will be loaded (or
        /// created if it doesn't exist).
        const char* config_dir;
        /// path to the default bootstrap.signed file included in installation, which will be used
        /// by default when no specific bootstrap is in the config file.
        const char* default_bootstrap;
        /// llarp_apple_init writes the IP address for the primary tunnel IP address here,
        /// null-terminated.
        char tunnel_ipv4_ip[INET_ADDRSTRLEN];
        /// llarp_apple_init writes the netmask of the tunnel address here, null-terminated.
        char tunnel_ipv4_netmask[INET_ADDRSTRLEN];
        /// Writes the IPv6 address for the tunnel here, null-terminated.
        char tunnel_ipv6_ip[INET6_ADDRSTRLEN];
        /// IPv6 address prefix.
        uint16_t tunnel_ipv6_prefix;

        /// The first upstream DNS server's IPv4 address the OS should use when in exit mode.
        /// (Currently on mac in exit mode we only support querying the first such configured
        /// server).
        char upstream_dns[INET_ADDRSTRLEN];
        uint16_t upstream_dns_port;

#ifdef MACOS_SYSTEM_EXTENSION
        /// DNS bind IP; llarp_apple_init writes the lokinet config value here so that we know (in
        /// Apple API code) what to set DNS to when lokinet gets turned on.  Null terminated.
        char dns_bind_ip[INET_ADDRSTRLEN];
#endif

        /// \defgroup callbacks Callbacks
        /// Callbacks we invoke for various operations that require glue into the Apple network
        /// extension APIs.  All of these except for ns_logger are passed the pointer provided to
        /// llarp_apple_start when invoked.
        /// @{

        /// simple wrapper around NSLog for lokinet message logging
        ns_logger_callback ns_logger;

        /// C function callback that will be called when we need to write a packet to the packet
        /// tunnel.  Will be passed AF_INET or AF_INET6, a void pointer to the data, and the size of
        /// the data in bytes.
        packet_writer_callback packet_writer;

        /// C function callback that will be called when lokinet is setup and ready to start
        /// receiving packets from the packet tunnel.  This should set up the read handler to
        /// deliver packets via llarp_apple_incoming.
        start_reading_callback start_reading;

        /// Callbacks invoked to add/remove routes to the tunnel.
        llarp_route_callbacks route_callbacks;

        /// @}
    } llarp_apple_config;

    /// Initializes a lokinet instance by initializing various objects and loading the configuration
    /// (if <config_dir>/lokinet.ini exists).  Does not actually start lokinet (call
    /// llarp_apple_start for that).
    ///
    /// Returns NULL if there was a problem initializing/loading the configuration, otherwise
    /// returns an opaque void pointer that should be passed into the other llarp_apple_* functions.
    ///
    /// \param config pointer to a llarp_apple_config where we get the various settings needed
    /// and return the ip/mask/dns fields needed for the tunnel.
    void* llarp_apple_init(llarp_apple_config* config);

    /// Starts the lokinet instance in a new thread.
    ///
    /// \param lokinet the void pointer returned by llarp_apple_init
    ///
    /// \param callback_context Opaque pointer that is passed into the various callbacks provided to
    /// llarp_apple_init.  This code does nothing with this pointer aside from passing it through to
    /// callbacks.
    ///
    /// \returns 0 on succesful startup, -1 on failure.
    int llarp_apple_start(void* lokinet, void* callback_context);

    /// Returns a pointer to the uv event loop.  Must have called llarp_apple_start already.
    uv_loop_t* llarp_apple_get_uv_loop(void* lokinet);

    /// Struct of packet data; a C array of tests gets passed to llarp_apple_incoming
    typedef struct llarp_incoming_packet
    {
        const void* bytes;
        size_t size;
    } llarp_incoming_packet;

    /// Called to deliver one or more incoming packets from the apple layer into lokinet.  Takes a C
    /// array of `llarp_incoming_packets` with pointers/sizes set to the individual new packets that
    /// have arrived.
    ///
    /// Returns the number of valid packets on success (which can be less than the number of
    /// provided packets, if some failed to parse), or -1 if there is no current active VPNInterface
    /// associated with the lokinet instance (which generally means llarp_apple_start wasn't called
    /// or failed, or lokinet is in the process of shutting down).
    int llarp_apple_incoming(void* lokinet, const llarp_incoming_packet* packets, size_t size);

    /// Stops a lokinet instance created with `llarp_apple_initialize`.  This waits for lokinet to
    /// shut down and rejoins the thread.  After this call the given pointer is no longer valid.
    void llarp_apple_shutdown(void* lokinet);

#ifdef __cplusplus
}  // extern "C"
#endif
