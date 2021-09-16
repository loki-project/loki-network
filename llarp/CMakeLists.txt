include(Version)

add_library(lokinet-util
  ${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp
  util/bencode.cpp
  util/buffer.cpp
  util/fs.cpp
  util/json.cpp
  util/logging/android_logger.cpp
  util/logging/buffer.cpp
  util/logging/file_logger.cpp
  util/logging/json_logger.cpp
  util/logging/logger.cpp
  util/logging/logger_internal.cpp
  util/logging/loglevel.cpp
  util/logging/ostream_logger.cpp
  util/logging/syslog_logger.cpp
  util/logging/win32_logger.cpp
  util/lokinet_init.c
  util/mem.cpp
  util/printer.cpp
  util/str.cpp
  util/thread/queue_manager.cpp
  util/thread/threading.cpp
  util/time.cpp)


add_dependencies(lokinet-util genversion)

target_include_directories(lokinet-util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR})

target_link_libraries(lokinet-util PUBLIC
  lokinet-cryptography
  nlohmann_json::nlohmann_json
  filesystem
  date::date
  oxenmq::oxenmq
)

if(ANDROID)
  target_link_libraries(lokinet-util PUBLIC log)
endif()

add_library(lokinet-platform
  STATIC
  # for networking
  ev/ev.cpp
  ev/ev_libuv.cpp
  net/ip.cpp
  net/ip_address.cpp
  net/ip_packet.cpp
  net/ip_range.cpp
  net/net.cpp
  net/net_int.cpp
  net/sock_addr.cpp
  vpn/packet_router.cpp
  vpn/platform.cpp
)

target_link_libraries(lokinet-platform PUBLIC lokinet-cryptography lokinet-util Threads::Threads base_libs uvw)


if (ANDROID)
  target_sources(lokinet-platform PRIVATE android/ifaddrs.c)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  target_sources(lokinet-platform PRIVATE linux/netns.cpp)

  if(NON_PC_TARGET)
    add_import_library(rt)
    target_link_libraries(lokinet-platform PUBLIC rt)
  endif()
endif()

if (WIN32)
  target_link_libraries(lokinet-platform PUBLIC iphlpapi fwpuclnt rpcrt4)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  target_include_directories(lokinet-platform SYSTEM PUBLIC /usr/local/include)
endif()

add_library(liblokinet
  STATIC
  config/config.cpp
  config/definition.cpp
  config/ini.cpp
  config/key_manager.cpp

  dns/message.cpp
  dns/name.cpp
  dns/question.cpp
  dns/rr.cpp
  dns/serialize.cpp
  dns/server.cpp
  dns/srv_data.cpp
  dns/unbound_resolver.cpp

  consensus/table.cpp
  consensus/reachability_testing.cpp

  bootstrap.cpp
  context.cpp
  crypto/crypto_libsodium.cpp
  crypto/crypto.cpp
  crypto/encrypted_frame.cpp
  crypto/types.cpp
  dht/context.cpp
  dht/dht.cpp
  dht/explorenetworkjob.cpp
  dht/localtaglookup.cpp
  dht/localrouterlookup.cpp
  dht/localserviceaddresslookup.cpp
  dht/message.cpp
  dht/messages/findintro.cpp
  dht/messages/findrouter.cpp
  dht/messages/gotintro.cpp
  dht/messages/gotrouter.cpp
  dht/messages/pubintro.cpp
  dht/messages/findname.cpp
  dht/messages/gotname.cpp
  dht/publishservicejob.cpp
  dht/recursiverouterlookup.cpp
  dht/serviceaddresslookup.cpp
  dht/taglookup.cpp

  endpoint_base.cpp
  
  exit/context.cpp
  exit/endpoint.cpp
  exit/exit_messages.cpp
  exit/policy.cpp
  exit/session.cpp
  handlers/exit.cpp
  handlers/tun.cpp
  hook/shell.cpp
  iwp/iwp.cpp
  iwp/linklayer.cpp
  iwp/message_buffer.cpp
  iwp/session.cpp
  link/link_manager.cpp
  link/session.cpp
  link/server.cpp
  messages/dht_immediate.cpp
  messages/link_intro.cpp
  messages/link_message_parser.cpp
  messages/relay.cpp
  messages/relay_commit.cpp
  messages/relay_status.cpp
  net/address_info.cpp
  net/exit_info.cpp
  net/traffic_policy.cpp
  nodedb.cpp
  path/ihophandler.cpp
  path/path_context.cpp
  path/path.cpp
  path/pathbuilder.cpp
  path/pathset.cpp
  path/transit_hop.cpp
  peerstats/peer_db.cpp
  peerstats/types.cpp
  pow.cpp
  profiling.cpp

  quic/address.cpp
  quic/client.cpp
  quic/connection.cpp
  quic/endpoint.cpp
  quic/null_crypto.cpp
  quic/server.cpp
  quic/stream.cpp
  quic/tunnel.cpp

  router_contact.cpp
  router_id.cpp
  router_version.cpp
  service/name.cpp
  router/outbound_message_handler.cpp
  router/outbound_session_maker.cpp
  router/rc_lookup_handler.cpp
  router/rc_gossiper.cpp
  router/router.cpp
  router/route_poker.cpp
  router/systemd_resolved.cpp
  routing/dht_message.cpp
  routing/message_parser.cpp
  routing/path_confirm_message.cpp
  routing/path_latency_message.cpp
  routing/path_transfer_message.cpp
  routing/transfer_traffic_message.cpp
  rpc/lokid_rpc_client.cpp
  rpc/rpc_server.cpp
  rpc/endpoint_rpc.cpp
  service/address.cpp
  service/async_key_exchange.cpp
  service/auth.cpp
  service/convotag.cpp
  service/context.cpp
  service/endpoint_state.cpp
  service/endpoint_util.cpp
  service/endpoint.cpp
  service/hidden_service_address_lookup.cpp
  service/identity.cpp
  service/info.cpp
  service/intro_set.cpp
  service/intro.cpp
  service/lns_tracker.cpp
  service/lookup.cpp
  service/name.cpp
  service/outbound_context.cpp
  service/protocol.cpp
  service/protocol_type.cpp
  service/router_lookup_job.cpp
  service/sendcontext.cpp
  service/session.cpp
  service/tag.cpp
)

set_target_properties(liblokinet PROPERTIES OUTPUT_NAME lokinet)

enable_lto(lokinet-util lokinet-platform liblokinet)
  
if(TRACY_ROOT)
  target_sources(liblokinet PRIVATE ${TRACY_ROOT}/TracyClient.cpp)
endif()

if(TESTNET)
  target_sources(liblokinet PRIVATE testnet.c)
endif()

if(WITH_HIVE)
  target_sources(liblokinet PRIVATE
    tooling/router_hive.cpp
    tooling/hive_router.cpp
    tooling/hive_context.cpp
  )
endif()

target_link_libraries(liblokinet PUBLIC cxxopts lokinet-platform lokinet-util lokinet-cryptography sqlite_orm ngtcp2)
target_link_libraries(liblokinet PRIVATE libunbound)


if(BUILD_LIBLOKINET)
  include(GNUInstallDirs)
  add_library(lokinet-shared SHARED lokinet_shared.cpp)
  target_link_libraries(lokinet-shared PUBLIC liblokinet)
  if(WIN32)
    set(CMAKE_SHARED_LIBRARY_PREFIX_CXX "")
  endif()
  set_target_properties(lokinet-shared PROPERTIES OUTPUT_NAME lokinet)
  if(WIN32)
    target_link_libraries(lokinet-shared PUBLIC ws2_32 iphlpapi -fstack-protector)
    install(TARGETS lokinet-shared DESTINATION bin COMPONENT liblokinet)
  else()
    install(TARGETS lokinet-shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT liblokinet)
  endif()
  add_log_tag(lokinet-shared)
endif()

if(APPLE)
  add_subdirectory(apple)
endif()

foreach(lokinet_lib liblokinet lokinet-platform lokinet-util lokinet-cryptography)
  add_log_tag(${lokinet_lib})
endforeach()

file(GLOB_RECURSE docs_SRC */*.hpp *.hpp)

set(DOCS_SRC ${docs_SRC} PARENT_SCOPE)
