#pragma once
#include <NetworkExtension/NetworkExtension.h>
#include <uv.h>

extern NSString* error_domain;

/**
 * "Trampoline" class that listens for UDP DNS packets when we have exit mode enabled.  These arrive
 * on localhost:1053 coming from lokinet's embedded libunbound (when exit mode is enabled), wraps
 * them via NetworkExtension's crappy UDP API, then sends responses back to libunbound to be
 * parsed/etc.  This class knows nothing about DNS, it is basically just a UDP packet forwarder, but
 * using Apple magic reinvented wheel wrappers that are oh so wonderful like everything Apple.
 *
 * So for a lokinet configuration of "upstream=1.1.1.1", when exit mode is OFF:
 * - DNS requests go unbound either to 127.0.0.1:53 directly (system extension) or bounced through
 *   TUNNELIP:53 (app extension), which forwards them (directly) to the upstream DNS server(s).
 * With exit mode ON:
 * - DNS requests go to unbound, as above, and unbound forwards them to 127.0.0.1:1053, which
 *   encapsulates them in Apple's god awful crap, then (on a response) sends them back to
 *   libunbound to be delivered back to the requestor.
 * (This assumes a non-lokinet DNS; .loki and .snode get handled before either of these).
 */
@interface LLARPDNSTrampoline : NSObject
{
    // The socket libunbound talks with:
    uv_udp_t request_socket;
    // The reply address.  This is a bit hacky: we configure libunbound to just use single address
    // (rather than a range) so that we don't have to worry about tracking different reply
    // addresses.
  @public
    struct sockaddr reply_addr;
    // UDP "session" aimed at the upstream DNS
  @public
    NWUDPSession* upstream;
    // Apple docs say writes could take time *and* the crappy Apple datagram write methods aren't
    // callable again until the previous write finishes.  Deal with this garbage API by queuing
    // everything than using a uv_async to process the queue.
  @public
    int write_ready;
  @public
    NSMutableArray<NSData*>* pending_writes;
    uv_async_t write_trigger;
}
- (void)startWithUpstreamDns:(NWUDPSession*)dns
                    listenIp:(NSString*)listenIp
                  listenPort:(uint16_t)listenPort
                      uvLoop:(uv_loop_t*)loop
           completionHandler:(void (^)(NSError* error))completionHandler;

- (void)flushWrites;

- (void)dealloc;

@end
