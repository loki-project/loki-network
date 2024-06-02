cmake_minimum_required(VERSION 3.13...3.24)  # 3.13 is buster's version

# Cmake 3.24+ breaks extraction timestamps by default, hurray, but the option to not break
# timestamps fails in cmake <3.24, extra hurray!
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    cmake_policy(SET CMP0135 OLD)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Has to be set before `project()`, and ignored on non-macos:
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.15 CACHE STRING "macOS deployment target (Apple clang only)")

option(BUILD_DAEMON "build lokinet daemon and associated utils" ON)
option(GRAPH_DEPENDENCIES "Produce graphviz representation of cmake dependencies" OFF)

set(LANGS C CXX)
if(APPLE AND BUILD_DAEMON)
  set(LANGS ${LANGS} OBJC Swift)
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang ${LANGS})
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()


project(lokinet
    VERSION 0.9.11
    DESCRIPTION "lokinet - IP packet onion router"
    LANGUAGES ${LANGS})

if(APPLE)
    # Apple build number: must be incremented to submit a new build for the same lokinet version,
    # should be reset to 0 when the lokinet version increments.
    set(LOKINET_APPLE_BUILD 5)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(DEFAULT_WITH_BOOTSTRAP ON)
if(APPLE)
  set(DEFAULT_WITH_BOOTSTRAP OFF)
endif()


# Core options
option(USE_AVX2 "enable avx2 code" OFF)
option(USE_NETNS "enable networking namespace support. Linux only" OFF)
option(NATIVE_BUILD "optimise for host system and FPU" ON)
option(WITH_EMBEDDED_LOKINET "build liblokinet.so for embedded lokinet" OFF)
option(XSAN "use sanitiser, if your system has it (requires -DCMAKE_BUILD_TYPE=Debug)" OFF)
option(USE_JEMALLOC "Link to jemalloc for memory allocations, if found" ON)
option(TESTNET "testnet build" OFF)
option(WITH_COVERAGE "generate coverage data" OFF)
option(WARNINGS_AS_ERRORS "treat all warnings as errors. turn off for development, on for release" OFF)
option(WITH_TESTS "build unit tests" OFF)
option(WITH_HIVE "build simulation stubs" OFF)
option(BUILD_PACKAGE "builds extra components for making an installer (with 'make package')" OFF)
option(WITH_BOOTSTRAP "build lokinet-bootstrap tool" ${DEFAULT_WITH_BOOTSTRAP})
option(WITH_PEERSTATS "build with experimental peerstats db support" OFF)
option(STRIP_SYMBOLS "strip off all debug symbols into an external archive for all executables built" OFF)

set(BOOTSTRAP_FALLBACK_MAINNET "${PROJECT_SOURCE_DIR}/contrib/bootstrap/mainnet.signed" CACHE PATH "Fallback bootstrap path (mainnet)")
set(BOOTSTRAP_FALLBACK_TESTNET "${PROJECT_SOURCE_DIR}/contrib/bootstrap/testnet.signed" CACHE PATH "Fallback bootstrap path (testnet)")

include(cmake/enable_lto.cmake)

option(CROSS_PLATFORM "cross compiler platform" "Linux")
option(CROSS_PREFIX "toolchain cross compiler prefix" "")

option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(BUILD_STATIC_DEPS "Download, build, and statically link against core dependencies" OFF)
option(STATIC_LINK "link statically against dependencies" ${BUILD_STATIC_DEPS})
if(BUILD_STATIC_DEPS AND NOT STATIC_LINK)
  message(FATAL_ERROR "Option BUILD_STATIC_DEPS requires STATIC_LINK to be enabled as well")
endif()

if(BUILD_STATIC_DEPS AND BUILD_SHARED_LIBS)
  message(FATAL_ERROR "Incompatible options: BUILD_STATIC_DEPS cannot be used with BUILD_SHARED_LIBS")
endif()

if(BUILD_STATIC_DEPS)
  set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
  include(cmake/StaticBuild.cmake)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(debug OFF)
if(CMAKE_BUILD_TYPE MATCHES "[Dd][Ee][Bb][Uu][Gg]")
  set(debug ON)
  add_definitions(-DLOKINET_DEBUG)
endif()

option(WARN_DEPRECATED "show deprecation warnings" OFF)

include(CheckCXXSourceCompiles)
include(CheckLibraryExists)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(cmake/target_link_libraries_system.cmake)
include(cmake/add_import_library.cmake)
include(cmake/libatomic.cmake)

if (STATIC_LINK)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
  message(STATUS "setting static library suffix search")
endif()

include(cmake/gui-option.cmake)

include(cmake/solaris.cmake)
include(cmake/win32.cmake)
include(cmake/macos.cmake)

# No in-source building
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out-of-source build.  Create a build directory and run 'cmake ${CMAKE_SOURCE_DIR} [options]'.")

# Always build PIC
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(cmake/unix.cmake)
include(cmake/check_for_std_optional.cmake)
#include(cmake/check_for_std_filesystem.cmake)

if(NOT WIN32)
  if(IOS OR ANDROID)
    set(NON_PC_TARGET ON)
  else()
    include(TargetArch)
    target_architecture(COMPILE_ARCH)
    if(COMPILE_ARCH MATCHES i386 OR COMPILE_ARCH MATCHES x86_64)
      set(NON_PC_TARGET OFF)
    else()
      set(NON_PC_TARGET ON)
    endif()
  endif()
endif()

find_package(PkgConfig REQUIRED)

if(NOT BUILD_STATIC_DEPS)
  pkg_check_modules(LIBUV libuv>=1.18.0 IMPORTED_TARGET)
endif()
if(LIBUV_FOUND AND NOT BUILD_STATIC_DEPS)
  add_library(libuv INTERFACE)
  target_link_libraries(libuv INTERFACE PkgConfig::LIBUV)
else()
  if(NOT BUILD_STATIC_DEPS)
    message(FATAL_ERROR "Could not find libuv >= 1.28.0; install it on your system or use -DBUILD_STATIC_DEPS=ON")
  endif()
endif()

if(NOT TARGET sodium)
# Allow -D DOWNLOAD_SODIUM=FORCE to download without even checking for a local libsodium
  option(DOWNLOAD_SODIUM "Allow libsodium to be downloaded and built locally if not found on the system" OFF)
  if(NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    pkg_check_modules(SODIUM libsodium>=1.0.18 IMPORTED_TARGET)
  endif()

  add_library(sodium INTERFACE)
  if(SODIUM_FOUND AND NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)
  else()
    if(NOT DOWNLOAD_SODIUM AND NOT BUILD_STATIC_DEPS)
      message(FATAL_ERROR "Could not find libsodium >= 1.0.18; either install it on your system or use -DDOWNLOAD_SODIUM=ON to download and build an internal copy")
    endif()
    message(STATUS "Sodium >= 1.0.18 not found, but DOWNLOAD_SODIUM specified, so downloading it")
    include(DownloadLibSodium)
    target_link_libraries(sodium INTERFACE sodium_vendor)
  endif()

  # Need this target export so that loki-mq properly picks up sodium
  export(TARGETS sodium NAMESPACE sodium:: FILE sodium-exports.cmake)
endif()

set(warning_flags -Wall -Wextra -Wno-unknown-pragmas -Wno-unused-function -Werror=vla)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  list(APPEND warning_flags -Wno-unknown-warning-option)
endif()

if(WARNINGS_AS_ERRORS)
  list(APPEND warning_flags -Werror -Wno-error=array-bounds)
endif()

list(APPEND warning_flags -Wno-deprecated-declarations)

add_library(lokinet-base-internal_warnings INTERFACE)

# If we blindly add these directly as compile_options then they get passed to swiftc on Apple and
# break, so we use a generate expression to set them only for C++/C/ObjC
target_compile_options(lokinet-base-internal_warnings INTERFACE "$<$<OR:$<COMPILE_LANGUAGE:CXX>,$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:OBJC>>:${warning_flags}>")

if(XSAN)
  string(APPEND CMAKE_CXX_FLAGS_DEBUG " -fsanitize=${XSAN} -fno-omit-frame-pointer -fno-sanitize-recover")
  foreach(type EXE MODULE SHARED STATIC)
    string(APPEND CMAKE_${type}_LINKER_FLAGS_DEBUG " -fsanitize=${XSAN} -fno-omit-frame-pointer -fno-sanitize-recover")
  endforeach()
  message(STATUS "Doing a ${XSAN} sanitizer build")
endif()

include(cmake/coverage.cmake)

# these vars are set by the cmake toolchain spec
if (WOW64_CROSS_COMPILE OR WIN64_CROSS_COMPILE)
  include(cmake/cross_compile.cmake)
endif()

if(NOT APPLE)
  if(NATIVE_BUILD)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL ppc64le)
      add_compile_options(-mcpu=native -mtune=native)
    else()
      add_compile_options(-march=native -mtune=native)
    endif()
  elseif(NOT NON_PC_TARGET)
    if (USE_AVX2)
      add_compile_options(-march=haswell -mtune=haswell -mfpmath=sse)
    else()
      # Public binary releases
      add_compile_options(-march=nocona -mtune=haswell -mfpmath=sse)
    endif()
  endif()
endif()

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

if(TESTNET)
  add_definitions(-DTESTNET)
  # 5 times slower than realtime
  # add_definitions(-DTESTNET_SPEED=5)
endif()

unset(GIT_VERSION)
unset(GIT_VERSION_REAL)

if(NOT GIT_VERSION)
  exec_program("git" ${CMAKE_CURRENT_SOURCE_DIR} ARGS "rev-parse --short HEAD" OUTPUT_VARIABLE GIT_VERSION_UNSTRIP)
  string(STRIP "${GIT_VERSION_UNSTRIP}" GIT_VERSION)
endif()

string(REGEX REPLACE "^fatal.*$" nogit GIT_VERSION_REAL "${GIT_VERSION}")

find_package(PkgConfig REQUIRED)

if (NOT BUILD_STATIC_DEPS)
  pkg_check_modules(UNBOUND libunbound REQUIRED IMPORTED_TARGET)
  add_library(libunbound INTERFACE)
  target_link_libraries(libunbound INTERFACE PkgConfig::UNBOUND)
endif()

pkg_check_modules(SD libsystemd IMPORTED_TARGET)
# Default WITH_SYSTEMD to true if we found it
option(WITH_SYSTEMD "enable systemd integration for sd_notify" ${SD_FOUND})

add_subdirectory(external)

# interface library for setting common includes, linkage and flags
add_library(lokinet-base INTERFACE)
target_include_directories(lokinet-base INTERFACE . include)
target_link_libraries(lokinet-base INTERFACE quic nlohmann_json::nlohmann_json)

add_library(lokinet-base-internal INTERFACE)
target_include_directories(lokinet-base-internal INTERFACE include/lokinet)

target_link_libraries(lokinet-base-internal INTERFACE lokinet-base-internal_warnings)

if(WITH_SYSTEMD AND (NOT ANDROID))
  if(NOT SD_FOUND)
    message(FATAL_ERROR "libsystemd not found")
  endif()
  target_link_libraries(lokinet-base INTERFACE PkgConfig::SD)
  target_compile_definitions(lokinet-base INTERFACE WITH_SYSTEMD)
endif()

if(USE_JEMALLOC AND NOT STATIC_LINK)
  pkg_check_modules(JEMALLOC jemalloc IMPORTED_TARGET)
  if(JEMALLOC_FOUND)
    target_link_libraries(lokinet-base INTERFACE PkgConfig::JEMALLOC)
  else()
    message(STATUS "jemalloc not found, not linking to jemalloc")
  endif()
else()
  message(STATUS "jemalloc support disabled")
endif()


if(ANDROID)
  target_link_libraries(lokinet-base INTERFACE log)
  target_compile_definitions(lokinet-base INTERFACE ANDROID)
  set(ANDROID_PLATFORM_SRC android/ifaddrs.c)
endif()

if(WITH_HIVE)
  add_definitions(-DLOKINET_HIVE)
endif()

add_subdirectory(crypto)
add_subdirectory(llarp)
if(BUILD_DAEMON)
  add_subdirectory(daemon)
endif()

if(WITH_HIVE)
  add_subdirectory(pybind)
endif()
if(WITH_TESTS OR WITH_HIVE)
  add_subdirectory(test)
endif()
if(ANDROID)
  add_subdirectory(jni)
endif()

add_subdirectory(docs)

include(cmake/gui.cmake)

if(APPLE)
  macos_target_setup()
endif()

# uninstall target
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

if(BUILD_PACKAGE AND NOT APPLE)
  include(cmake/installer.cmake)
endif()

if(TARGET package)
  add_dependencies(package assemble_gui)
endif()
