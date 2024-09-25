#include "DNSTrampoline.h"

#include <uv.h>

NSString* error_domain = @"org.lokinet";

// Receiving an incoming packet, presumably from libunbound.  NB: this is called from the libuv
// event loop.
static void on_request(
    uv_udp_t* socket, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    (void)flags;
    if (nread < 0)
    {
        NSLog(@"Read error: %s", uv_strerror(nread));
        free(buf->base);
        return;
    }

    if (nread == 0 || !addr)
    {
        if (buf)
            free(buf->base);
        return;
    }

    LLARPDNSTrampoline* t = (__bridge LLARPDNSTrampoline*)socket->data;

    // We configure libunbound to use just one single port so we'll just send replies to the last
    // port to talk to us.  (And we're only listening on localhost in the first place).
    t->reply_addr = *addr;

    // NSData takes care of calling free(buf->base) for us with this constructor:
    [t->pending_writes addObject:[NSData dataWithBytesNoCopy:buf->base length:nread]];

    [t flushWrites];
}

static void on_sent(uv_udp_send_t* req, int status)
{
    (void)status;
    NSArray<NSData*>* datagrams = (__bridge_transfer NSArray<NSData*>*)req->data;
    (void)datagrams;
    free(req);
}

// NB: called from the libuv event loop (so we don't have to worry about the above and this one
// running at once from different threads).
static void write_flusher(uv_async_t* async)
{
    LLARPDNSTrampoline* t = (__bridge LLARPDNSTrampoline*)async->data;
    if (t->pending_writes.count == 0)
        return;

    NSArray<NSData*>* data = [NSArray<NSData*> arrayWithArray:t->pending_writes];
    [t->pending_writes removeAllObjects];
    __weak LLARPDNSTrampoline* weakSelf = t;
    [t->upstream writeMultipleDatagrams:data
                      completionHandler:^(NSError* error) {
                        if (error)
                            NSLog(@"Failed to send request to upstream DNS: %@", error);

                        // Trigger another flush in case anything built up while Apple was doing its
                        // things.  Just call it unconditionally (rather than checking the queue)
                        // because this handler is probably running in some other thread.
                        [weakSelf flushWrites];
                      }];
}

static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

@implementation LLARPDNSTrampoline

- (void)startWithUpstreamDns:(NWUDPSession*)dns
                    listenIp:(NSString*)listenIp
                  listenPort:(uint16_t)listenPort
                      uvLoop:(uv_loop_t*)loop
           completionHandler:(void (^)(NSError* error))completionHandler
{
    NSLog(@"Setting up trampoline");
    pending_writes = [[NSMutableArray<NSData*> alloc] init];
    write_trigger.data = (__bridge void*)self;
    uv_async_init(loop, &write_trigger, write_flusher);

    request_socket.data = (__bridge void*)self;
    uv_udp_init(loop, &request_socket);
    struct sockaddr_in recv_addr;
    uv_ip4_addr(listenIp.UTF8String, listenPort, &recv_addr);
    int ret = uv_udp_bind(&request_socket, (const struct sockaddr*)&recv_addr, UV_UDP_REUSEADDR);
    if (ret < 0)
    {
        NSString* errstr = [NSString stringWithFormat:@"Failed to start DNS trampoline: %s", uv_strerror(ret)];
        NSError* err = [NSError errorWithDomain:error_domain code:ret userInfo:@{@"Error": errstr}];
        NSLog(@"%@", err);
        return completionHandler(err);
    }
    uv_udp_recv_start(&request_socket, alloc_buffer, on_request);

    NSLog(@"Starting DNS trampoline");

    upstream = dns;
    __weak LLARPDNSTrampoline* weakSelf = self;
    [upstream
        setReadHandler:^(NSArray<NSData*>* datagrams, NSError* error) {
          // Reading a reply back from the UDP socket used to talk to upstream
          if (error)
          {
              NSLog(@"Reader handler failed: %@", error);
              return;
          }
          LLARPDNSTrampoline* strongSelf = weakSelf;
          if (!strongSelf || datagrams.count == 0)
              return;

          uv_buf_t* buffers = malloc(datagrams.count * sizeof(uv_buf_t));
          size_t buf_count = 0;
          for (NSData* packet in datagrams)
          {
              buffers[buf_count].base = (void*)packet.bytes;
              buffers[buf_count].len = packet.length;
              buf_count++;
          }
          uv_udp_send_t* uvsend = malloc(sizeof(uv_udp_send_t));
          uvsend->data = (__bridge_retained void*)datagrams;
          int ret =
              uv_udp_send(uvsend, &strongSelf->request_socket, buffers, buf_count, &strongSelf->reply_addr, on_sent);
          free(buffers);
          if (ret < 0)
              NSLog(@"Error returning DNS responses to unbound: %s", uv_strerror(ret));
        }
          maxDatagrams:NSUIntegerMax];

    completionHandler(nil);
}

- (void)flushWrites
{
    uv_async_send(&write_trigger);
}

- (void)dealloc
{
    NSLog(@"Stopping DNS trampoline");
    uv_close((uv_handle_t*)&request_socket, NULL);
    uv_close((uv_handle_t*)&write_trigger, NULL);
}

@end
