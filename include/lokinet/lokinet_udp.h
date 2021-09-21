#pragma once

#include "lokinet_context.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /// information about a udp flow
  struct lokinet_udp_flowinfo
  {
    /// remote endpoint's .loki or .snode address
    char remote_addr[256];
    /// remote endpont's port
    int remote_port;
    /// the socket id for this flow used for i/o purposes and closing this socket
    int socket_id;
  };

  /// a result from a lokinet_udp_bind call
  struct lokinet_udp_bind_result
  {
    /// a socket id used to close a lokinet udp socket
    int socket_id;
  };

  /// flow acceptor hook, return 0 success, return nonzero with errno on failure
  typedef int (*lokinet_udp_flow_filter)(
      void* /*user*/,
      const struct lokinet_udp_flowinfo* /* remote address */,
      void** /* flow-userdata */,
      int* /* timeout seconds */);

  /// hook function for handling packets
  typedef void (*lokinet_udp_flow_recv_func)(
      const struct lokinet_udp_flowinfo* /* remote address */,
      char* /* data pointer */,
      size_t /* data length */,
      void* /* flow-userdata */);

  /// hook function for flow timeout
  typedef void (*lokinet_udp_flow_timeout_func)(
      const struct lokinet_udp_flowinfo* /* remote address  */, void* /* flow-userdata */);

  /// inbound listen udp socket
  /// expose udp port exposePort to the void
  ////
  /// @param filter MUST be non null, pointing to a flow filter for accepting new udp flows, called
  /// with user data
  ///
  /// @param recv MUST be non null, pointing to a packet handler function for each flow, called
  /// with per flow user data provided by filter function if accepted
  ///
  /// @param timeout MUST be non null,
  /// pointing to a cleanup function to clean up a stale flow, staleness determined by the value
  /// given by the filter function returns 0 on success
  ///
  /// @returns nonzero on error in which it is an errno value
  int EXPORT
  lokinet_udp_bind(
      int exposedPort,
      lokinet_udp_flow_filter filter,
      lokinet_udp_flow_recv_func recv,
      lokinet_udp_flow_timeout_func timeout,
      void* user,
      struct lokinet_udp_bind_result* result,
      struct lokinet_context* ctx);

  /// @brief establish a udp flow to remote endpoint
  ///
  /// @param remote the remote address to establish to
  ///
  /// @param ctx the lokinet context to use
  ///
  /// @return 0 on success, non zero errno on fail
  int EXPORT
  lokinet_udp_establish(const struct lokinet_udp_flowinfo* remote, struct lokinet_context* ctx);

  /// @brief send on an established flow to remote endpoint
  ///
  /// @param flowinfo populated after call on success
  ///
  /// @param ptr pointer to data to send
  ///
  /// @param len the length of the data
  ///
  /// @param ctx the lokinet context to use
  ///
  /// @returns 0 on success and non zero errno on fail
  int EXPORT
  lokinet_udp_flow_send(
      const struct lokinet_udp_flowinfo* remote,
      const void* ptr,
      size_t len,
      struct lokinet_ctx* ctx);

#ifdef __cplusplus
}
#endif
