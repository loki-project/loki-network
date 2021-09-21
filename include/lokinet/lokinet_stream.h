#pragma once

#include "lokinet_context.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /// the result of a lokinet stream mapping attempt
#pragma pack(1)
  struct lokinet_stream_result
  {
    /// set to zero on success otherwise the error that happened
    /// use strerror(3) to get printable string of this error
    int error;

    /// the local ip address we mapped the remote endpoint to
    /// null terminated
    char local_address[256];
    /// the local port we mapped the remote endpoint to
    int local_port;
    /// the id of the stream we created
    int stream_id;
  };
#pragma pack()

  /// connect out to a remote endpoint
  /// remoteAddr is in the form of "name:port"
  /// localAddr is either NULL for any or in the form of "ip:port" to bind to an explicit address
  void EXPORT
  lokinet_outbound_stream(
      struct lokinet_stream_result* result,
      const char* remoteAddr,
      const char* localAddr,
      struct lokinet_context* context);

  /// stream accept filter determines if we should accept a stream or not
  /// return 0 to accept
  /// return -1 to explicitly reject
  /// return -2 to silently drop
  typedef int (*lokinet_stream_filter)(const char* remote, uint16_t port, void*);

  /// set stream accepter filter
  /// passes user parameter into stream filter as void *
  /// returns stream id
  int EXPORT
  lokinet_inbound_stream_filter(
      lokinet_stream_filter acceptFilter, void* user, struct lokinet_context* context);

  /// simple stream acceptor
  /// simple variant of lokinet_inbound_stream_filter that maps port to localhost:port
  int EXPORT
  lokinet_inbound_stream(uint16_t port, struct lokinet_context* context);

  void EXPORT
  lokinet_close_stream(int stream_id, struct lokinet_context* context);

#ifdef __cplusplus
}
#endif
