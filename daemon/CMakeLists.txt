set(exetargets lokinet)

add_library(lokinet_daemon STATIC utils.cpp)
target_link_libraries(lokinet_daemon PUBLIC lokinet-base lokinet-core)

if(APPLE)
  add_executable(lokinet lokinet.swift)
  target_compile_options(lokinet BEFORE PRIVATE -target x86_64-apple-macos${CMAKE_OSX_DEPLOYMENT_TARGET})
else()
  add_executable(lokinet lokinet.cpp)
endif()

add_executable(lokinet-cntrl lokinet-cntrl.cpp)
enable_lto(lokinet lokinet-cntrl)
list(APPEND exetargets lokinet-cntrl)

if(WITH_BOOTSTRAP)
  add_executable(lokinet-bootstrap lokinet-bootstrap.cpp)
  list(APPEND exetargets lokinet-bootstrap)
  enable_lto(lokinet-bootstrap)
endif()


set(should_install ON)
set(SETCAP)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  option(WITH_SETCAP "use setcap when installing" ON)
  if(WITH_SETCAP)
    find_program(SETCAP NAMES setcap HINTS /sbin /usr/sbin)
    if(SETCAP)
      message(STATUS "Found setcap binary: ${SETCAP}")
    else()
      message(WARNING "cannot find setcap binary you will not be able use the install targets unless you use -DWITH_SETCAP=OFF")
      set(should_install OFF)
    endif()
  endif()
endif()

if(WITH_BOOTSTRAP)
  target_link_libraries(lokinet-bootstrap PUBLIC cpr::cpr)
  if(NOT WIN32)
    find_package(OpenSSL REQUIRED)
    # because debian sid's curl doesn't link against openssl for some godawful cursed reason
    target_link_libraries(lokinet-bootstrap PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  endif()
endif()

# cmake interface library for bunch of cmake hacks to fix final link order
add_library(hax_and_shims_for_cmake INTERFACE)
if(WIN32)
  target_link_libraries(hax_and_shims_for_cmake INTERFACE uvw oxenmq::oxenmq -lws2_32 -lshlwapi -ldbghelp -luser32 -liphlpapi -lpsapi -luserenv)
endif()

foreach(exe ${exetargets})
  if(WIN32)
    target_sources(${exe} PRIVATE ${CMAKE_BINARY_DIR}/${exe}.rc)
    target_link_libraries(${exe} PRIVATE -static-libstdc++ -static-libgcc --static -Wl,--pic-executable,-e,mainCRTStartup,--subsystem,console:5.00)
  elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    target_link_directories(${exe} PRIVATE /usr/local/lib)
  endif()
  target_link_libraries(${exe} PRIVATE lokinet_daemon)
  if(STRIP_SYMBOLS)
    add_custom_command(TARGET ${exe}
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS --only-keep-debug $<TARGET_FILE:${exe}> $<TARGET_FILE:${exe}>.debug
      COMMAND ${CMAKE_STRIP} ARGS --strip-all $<TARGET_FILE:${exe}>)
  endif()
  target_include_directories(${exe} PUBLIC "${PROJECT_SOURCE_DIR}")
  if(should_install)
    if(APPLE)
      install(TARGETS ${exe}
        BUNDLE DESTINATION "${PROJECT_BINARY_DIR}"
        RUNTIME DESTINATION "."
        COMPONENT lokinet)
    else()
      install(TARGETS ${exe} RUNTIME DESTINATION bin COMPONENT lokinet)
    endif()
  endif()
endforeach()

target_link_libraries(lokinet PRIVATE CLI11)
target_link_libraries(lokinet-cntrl PRIVATE CLI11)

if(WITH_SETCAP)
  install(CODE "execute_process(COMMAND ${SETCAP} cap_net_admin,cap_net_bind_service=+eip ${CMAKE_INSTALL_PREFIX}/bin/lokinet)")
endif()

if(STRIP_SYMBOLS)
  add_custom_target(symbols ALL
    COMMAND ${CMAKE_COMMAND} -E tar cJf ${CMAKE_CURRENT_BINARY_DIR}/debug-symbols.tar.xz $<TARGET_FILE:lokinet>.debug
    DEPENDS lokinet)
endif()
