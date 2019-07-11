add_definitions(-DUNIX)
add_definitions(-DPOSIX)

include_directories(/usr/local/include)

if (STATIC_LINK_RUNTIME)
  find_library(UV_LIB NAMES libuv.a)
else()
  find_library(UV_LIB NAMES uv)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(FS_LIB stdc++fs)
  get_filename_component(LIBTUNTAP_IMPL ${TT_ROOT}/tuntap-unix-linux.c ABSOLUTE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Android")
  set(FS_LIB stdc++fs)
  get_filename_component(LIBTUNTAP_IMPL ${TT_ROOT}/tuntap-unix-linux.c ABSOLUTE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(LIBTUNTAP_IMPL ${TT_ROOT}/tuntap-unix-openbsd.c ${TT_ROOT}/tuntap-unix-bsd.c)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
  set(LIBTUNTAP_IMPL ${TT_ROOT}/tuntap-unix-netbsd.c ${TT_ROOT}/tuntap-unix-bsd.c)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "DragonFly")
  find_library(FS_LIB NAMES c++experimental)
  set(LIBTUNTAP_IMPL ${TT_ROOT}/tuntap-unix-freebsd.c ${TT_ROOT}/tuntap-unix-bsd.c)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin" OR ${CMAKE_SYSTEM_NAME} MATCHES "iOS")
  find_library(FS_LIB NAMES c++fs c++experimental stdc++fs)

  if(FS_LIB STREQUAL FS_LIB-NOTFOUND)
    add_subdirectory(vendor)
    include_directories("${CMAKE_CURRENT_LIST_DIR}/../vendor/cppbackport-master/lib")
    add_definitions(-DLOKINET_USE_CPPBACKPORT)
    set(FS_LIB cppbackport)
  endif()

  set(LIBTUNTAP_IMPL ${TT_ROOT}/tuntap-unix-darwin.c ${TT_ROOT}/tuntap-unix-bsd.c)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
  set(LIBTUNTAP_IMPL ${TT_ROOT}/tuntap-unix-sunos.c)
else()
  message(FATAL_ERROR "Your operating system is not supported yet")
endif()


set(EXE_LIBS ${STATIC_LIB} libutp)

if(RELEASE_MOTTO)
  add_definitions(-DLLARP_RELEASE_MOTTO="${RELEASE_MOTTO}")
endif()
