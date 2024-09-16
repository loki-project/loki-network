include(Version)

# Add an internal lokinet static library target, enables LTO (if enabled) on the target,
# and links it to the common lokinet-base interface.
# Invoke with the target/library name (e.g. "lokinet-foo") and list of source files, e.g.
#     lokinet_add_library(lokinet-foo foo/source1.cpp foo/source2.cpp)
function(lokinet_add_library libname)
    add_library(${libname} STATIC ${ARGN})
    target_link_libraries(${libname} PUBLIC lokinet-base PRIVATE lokinet-base-internal)
    enable_lto(${libname})
endfunction()

lokinet_add_library(lokinet-cryptography
  crypto/crypto.cpp
  crypto/types.cpp
  crypto/key_manager.cpp
)

# Functional objects use by lokinet-core and other libraries
# needed by vpn/ router/ rpc/ handlers/ net/ link/
lokinet_add_library(lokinet-core-utils
  # endpoint_base.cpp

  auth/file_auth.cpp
  auth/rpc_auth.cpp
  auth/session_auth.cpp
  
  handlers/session.cpp
  handlers/tun.cpp
  
  service/identity.cpp
  service/info.cpp
  service/intro.cpp # path
  service/intro_set.cpp
  service/name.cpp
  
  vpn/egres_packet_router.cpp
)
  
lokinet_add_library(lokinet-core
  context.cpp
  
  consensus/reachability_testing.cpp
  
  link/link_manager.cpp
  
  router/router.cpp
  router/route_poker.cpp
  
  service/types.cpp

  session/session.cpp
)

lokinet_add_library(lokinet-rpc
  rpc/json_binary_proxy.cpp
  rpc/json_conversions.cpp
  rpc/rpc_client.cpp
  rpc/rpc_request_parser.cpp
  rpc/rpc_server.cpp
)

lokinet_add_library(lokinet-wire
  link/connection.cpp
  link/contacts.cpp
  link/link_manager.cpp
  link/tunnel.cpp
)

# config, crypto, timeplace, nodedb, bootstrap.cpp, net, router
lokinet_add_library(lokinet-utils
  ${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp
  util/buffer.cpp
  util/file.cpp
  util/logging/buffer.cpp
  util/mem.cpp
  util/str.cpp
  util/thread/threading.cpp
  util/thread/queue_manager.cpp  
  util/time.cpp
)

add_dependencies(lokinet-utils genversion)

# Addressing and event loop files used by lokinet-core and other libraries
# needed by rpc/ link/ service/ config/ path/ dht/
lokinet_add_library(lokinet-addressing
  address/address.cpp
  address/ip_packet.cpp
  address/ip_range.cpp
  address/keys.cpp
  address/utils.cpp

  ev/loop.cpp
  ev/tcp.cpp
  ev/types.cpp
  ev/udp.cpp

  net/ip.cpp
  net/net_int.cpp

  router_contact.cpp    # TODO: move these + router_id.cpp to lokinet-core-utils..?
  router_contact_local.cpp
  router_contact_remote.cpp
  router_id.cpp
  router_version.cpp  # to be deleted shortly

  service/tag.cpp
)

# lokinet-platform holds all platform specific code
lokinet_add_library(lokinet-platform
  net/interface_info.cpp
  vpn/packet_router.cpp
  vpn/platform.cpp
)

if (ANDROID)
  target_sources(lokinet-platform PRIVATE android/ifaddrs.c util/nop_service_manager.cpp)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  target_sources(lokinet-platform PRIVATE linux/dbus.cpp)
  if(WITH_SYSTEMD)
    target_sources(lokinet-platform PRIVATE linux/sd_service_manager.cpp)
  else()
    target_sources(lokinet-platform PRIVATE util/nop_service_manager.cpp)
  endif()
endif()

if (WIN32)
  target_sources(lokinet-platform PRIVATE
    net/win32.cpp
    vpn/win32.cpp
    win32/service_manager.cpp
    win32/exec.cpp
    win32/dll.cpp
    win32/exception.cpp
    win32/wintun.cpp
    win32/windivert.cpp)
  target_include_directories(lokinet-platform PRIVATE ${CMAKE_BINARY_DIR}/wintun/include/ ${CMAKE_BINARY_DIR}/WinDivert-${WINDIVERT_VERSION}/include/)
else()
  target_sources(lokinet-platform PRIVATE
    net/posix.cpp)
endif()

if(APPLE)
  add_subdirectory(apple)
  target_sources(lokinet-platform PRIVATE util/nop_service_manager.cpp)
endif()

# lokinet-dns is the dns parsing and hooking library that we use to
# parse modify and reconstitute dns wire proto, dns queries and RR
lokinet_add_library(lokinet-dns
  dns/message.cpp   # dns/server
  dns/name.cpp      # srv_data, question, rr
  dns/platform.cpp
  dns/question.cpp  # message
  dns/rr.cpp
  dns/serialize.cpp
  dns/server.cpp
  dns/srv_data.cpp  
)

# platform specific bits and bobs for setting dns
add_library(lokinet-dns-platform INTERFACE)
if(WITH_SYSTEMD)
  lokinet_add_library(lokinet-dns-systemd dns/nm_platform.cpp dns/sd_platform.cpp)
  target_link_libraries(lokinet-dns-platform INTERFACE lokinet-dns-systemd)
endif()

# lokinet-nodedb holds all types and logic for storing parsing and constructing
# nodedb data published to the network and versions of it stored locally
lokinet_add_library(lokinet-nodedb
  bootstrap.cpp   # config, router.hpp
  net/traffic_policy.cpp  # config, intro_set
  nodedb.cpp
  profiling.cpp # path, router, service::endpoint
)

set(BOOTSTRAP_FALLBACKS)
foreach(bs IN ITEMS MAINNET TESTNET)
  if(BOOTSTRAP_FALLBACK_${bs})
    message(STATUS "Building with ${bs} fallback bootstrap path \"${BOOTSTRAP_FALLBACK_${bs}}\"")
    file(READ "${BOOTSTRAP_FALLBACK_${bs}}" bs_data HEX)
    if(bs STREQUAL TESTNET)
      set(network "testnet")
    elseif(bs STREQUAL MAINNET)
      set(network "lokinet")
    else()
      string(TOLOWER "${bs}" network)
    endif()
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "\\\\x\\1" bs_data "${bs_data}")
    set(BOOTSTRAP_FALLBACKS "${BOOTSTRAP_FALLBACKS}{\"${network}\"s, \"${bs_data}\"sv},\n")
  endif()
endforeach()
configure_file("bootstrap-fallbacks.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/bootstrap-fallbacks.cpp" @ONLY)
target_sources(lokinet-nodedb PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/bootstrap-fallbacks.cpp")

# lokinet-config is for all configuration types and parsers
lokinet_add_library(lokinet-config
  config/config.cpp
  config/definition.cpp
  config/ini.cpp
)

# All path objects; link directly to lokinet-core
lokinet_add_library(lokinet-path
  path/path.cpp
  path/path_context.cpp
  path/path_handler.cpp
  path/transit_hop.cpp
)

# Link libraries to their internals
target_link_libraries(lokinet-core-utils PUBLIC lokinet-dns)
target_link_libraries(lokinet-core PUBLIC lokinet-core-utils)

# Link lokinet-dns to alternate libraries
target_link_libraries(lokinet-dns PUBLIC lokinet-dns-platform)

target_link_libraries(lokinet-wire PUBLIC lokinet-addressing)
target_link_libraries(lokinet-dns PUBLIC lokinet-utils lokinet-cryptography lokinet-config)
target_link_libraries(lokinet-nodedb PUBLIC lokinet-addressing lokinet-cryptography)
target_link_libraries(lokinet-platform PUBLIC lokinet-cryptography)
target_link_libraries(lokinet-rpc PUBLIC lokinet-wire)
target_link_libraries(lokinet-addressing PUBLIC lokinet-utils lokinet-cryptography)
target_link_libraries(lokinet-wire PUBLIC lokinet-cryptography)
target_link_libraries(lokinet-config PUBLIC lokinet-cryptography)

target_link_libraries(lokinet-dns
  PUBLIC
  lokinet-addressing
)

target_link_libraries(lokinet-path
  PUBLIC
  lokinet-addressing
)

target_link_libraries(lokinet-core-utils 
  PUBLIC 
  lokinet-config
  lokinet-platform
  lokinet-rpc 
  lokinet-wire 
)

target_link_libraries(lokinet-cryptography
  PUBLIC
  lokinet-libcrypt
  lokinet-libntrup
)

target_link_libraries(lokinet-utils
  PUBLIC
  lokinet-cryptography
)

# cross linkage
target_link_libraries(lokinet-core 
  PUBLIC 
  lokinet-cryptography
  lokinet-nodedb
  lokinet-path
  lokinet-rpc 
  lokinet-wire 
)


target_link_libraries(lokinet-base 
  INTERFACE 
  
  libevent::core
  libevent::threads
  libevent::extra

  Threads::Threads

  oxenc::oxenc 
  oxen::logging 
  oxenmq::oxenmq 
  
  libunbound

  sodium
)


# target_link_libraries(lokinet-rpc PUBLIC oxenmq::oxenmq)
# target_link_libraries(lokinet-core PUBLIC oxenmq::oxenmq)
# target_link_libraries(lokinet-config PUBLIC oxenmq::oxenmq)
# target_link_libraries(lokinet-nodedb PUBLIC oxenmq::oxenmq)
# target_link_libraries(lokinet-path PUBLIC oxenmq::oxenmq)
# target_link_libraries(lokinet-platform PUBLIC oxenmq::oxenmq Threads::Threads)
# target_link_libraries(lokinet-cryptography PUBLIC sodium)
# target_link_libraries(lokinet-dns PUBLIC libunbound)
# target_link_libraries(lokinet-utils PUBLIC nlohmann_json::nlohmann_json)
# target_link_libraries(lokinet-wire PUBLIC oxenmq::oxenmq quic)

if(WITH_EMBEDDED_LOKINET)
  include(GNUInstallDirs)
  add_library(lokinet-shared SHARED lokinet_shared.cpp)
  # target_link_libraries(lokinet-shared PUBLIC lokinet-amalgum)
  target_link_libraries(lokinet-shared PUBLIC lokinet-core)
  if(WIN32)
    set(CMAKE_SHARED_LIBRARY_PREFIX_CXX "")
  endif()
  set_target_properties(lokinet-shared PROPERTIES OUTPUT_NAME lokinet)
  if(WIN32)
    target_link_libraries(lokinet-shared PUBLIC ws2_32 iphlpapi -fstack-protector)
    install(TARGETS lokinet-shared DESTINATION bin COMPONENT liblokinet)
  elseif(NOT APPLE)
    install(TARGETS lokinet-shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT liblokinet)
  endif()
endif()

file(GLOB_RECURSE docs_SRC */*.hpp *.hpp)
set(DOCS_SRC ${docs_SRC} PARENT_SCOPE)
