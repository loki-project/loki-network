option(SUBMODULE_CHECK "Enables checking that vendored library submodules are up to date" ON)
if(SUBMODULE_CHECK)
  find_package(Git)
  if(GIT_FOUND)
    function(check_submodule relative_path)
      execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
      execute_process(COMMAND git rev-parse "HEAD:external/${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
      string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
      if (upToDate)
        message(STATUS "Submodule 'external/${relative_path}' is up-to-date")
      else()
        message(FATAL_ERROR "Submodule 'external/${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
      endif()

      # Extra arguments check nested submodules
      foreach(submod ${ARGN})
        execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/${submod} OUTPUT_VARIABLE localHead)
        execute_process(COMMAND git rev-parse "HEAD:${submod}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE checkedHead)
        string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
        if (NOT upToDate)
            message(FATAL_ERROR "Nested submodule '${relative_path}/${submod}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DSUBMODULE_CHECK=OFF")
        endif()
      endforeach()
    endfunction ()

    message(STATUS "Checking submodules")
    check_submodule(CLI11)
    check_submodule(cpr)
    check_submodule(libevent)
    check_submodule(nlohmann)
    check_submodule(oxen-encoding)
    check_submodule(oxen-libquic)
    check_submodule(oxen-mq)
    check_submodule(pybind11)
    check_submodule(sqlite_orm)
  endif()
endif()

macro(system_or_submodule BIGNAME smallname pkgconf subdir)
  option(FORCE_${BIGNAME}_SUBMODULE "force using ${smallname} submodule" OFF)
  if(NOT BUILD_STATIC_DEPS AND NOT FORCE_${BIGNAME}_SUBMODULE AND NOT FORCE_ALL_SUBMODULES)
    pkg_check_modules(${BIGNAME} ${pkgconf} IMPORTED_TARGET)
  endif()
  if(${BIGNAME}_FOUND)
    add_library(${smallname} INTERFACE)
    if(NOT TARGET PkgConfig::${BIGNAME} AND CMAKE_VERSION VERSION_LESS "3.21")
      # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
    else()
      target_link_libraries(${smallname} INTERFACE PkgConfig::${BIGNAME})
    endif()
    message(STATUS "Found system ${smallname} ${${BIGNAME}_VERSION}")
  else()
    message(STATUS "using ${smallname} submodule")
    add_subdirectory(${subdir})
  endif()
  if(NOT TARGET ${smallname}::${smallname})
    add_library(${smallname}::${smallname} ALIAS ${smallname})
  endif()
endmacro()

# libevent
set(EVENT__LIBRARY_TYPE "STATIC" CACHE STRING "" FORCE)
set(EVENT__DISABLE_MBEDTLS ON CACHE BOOL "" FORCE)
set(EVENT__DISABLE_MBEDTLS ON CACHE BOOL "" FORCE)
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "" FORCE)
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "" FORCE)
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "" FORCE)
set(EVENT__DISABLE_TESTS ON CACHE BOOL "" FORCE)
add_subdirectory(libevent EXCLUDE_FROM_ALL)

add_library(libevent::core ALIAS event_core)
add_library(libevent::threads ALIAS event_pthreads)
add_library(libevent::extra ALIAS event_extra)


system_or_submodule(OXENC oxenc liboxenc>=1.0.10 oxen-encoding)
system_or_submodule(OXENMQ oxenmq liboxenmq>=1.2.14 oxen-mq)

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
system_or_submodule(NLOHMANN nlohmann_json nlohmann_json>=3.7.0 nlohmann)

if(WITH_HIVE)
  add_subdirectory(pybind11 EXCLUDE_FROM_ALL)
endif()

system_or_submodule(CLI11 CLI11 CLI11>=2.2.0 CLI11)

if(WITH_PEERSTATS)
  add_library(sqlite_orm INTERFACE)
  target_include_directories(sqlite_orm SYSTEM INTERFACE sqlite_orm/include)
  if(NOT TARGET sqlite3)
    add_library(sqlite3 INTERFACE)
    pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
    target_link_libraries(sqlite3 INTERFACE PkgConfig::SQLITE3)
  endif()
  target_link_libraries(sqlite_orm INTERFACE sqlite3)
endif()

add_subdirectory(oxen-libquic)

# cpr configuration.  Ideally we'd just do this via add_subdirectory, but cpr's cmake requires
# 3.15+, and we target lower than that (and this is fairly simple to build).
if(WITH_BOOTSTRAP)
  if(NOT BUILD_STATIC_DEPS)
    find_package(CURL "7.71.0" COMPONENTS HTTP HTTPS SSL)

    if(CURL_FOUND)
      if(NOT (CURL_VERSION_STRING VERSION_GREATER_EQUAL "7.71.0"))
        message(STATUS "System curl version (${CURL_VERSION_STRING}) is too old; using submodule...")
        set(USE_CURL_SUBMODULE TRUE)
      else()
        set(USE_CURL_SUBMODULE FALSE)
      endif()
    else()
      message(STATUS "Could not find system curl; using submodule...")
      set(USE_CURL_SUBMODULE TRUE)
    endif()

    if(USE_CURL_SUBMODULE)

      SET(CURL_ZLIB OFF CACHE STRING "" FORCE)
      set(HTTP_ONLY ON CACHE INTERNAL "" FORCE)
      set(BUILD_CURL_EXE OFF CACHE INTERNAL "" FORCE)
      set(BUILD_TESTING OFF)
      set(CURL_ENABLE_SSL OFF CACHE INTERNAL "" FORCE)
      set(CURL_CA_PATH "none" CACHE INTERNAL "" FORCE)
      set(CURL_USE_SCHANNEL OFF CACHE INTERNAL "" FORCE)
      set(CURL_WINDOWS_SSPI OFF CACHE INTERNAL "" FORCE)
      set(CURL_USE_OPENSSL OFF CACHE INTERNAL "" FORCE)
      set(CURL_USE_SECTRANSP OFF CACHE INTERNAL "" FORCE)
      set(CURL_USE_MBEDTLS OFF CACHE INTERNAL "" FORCE)
      
      FetchContent_Declare(curl
                           URL                    https://github.com/curl/curl/releases/download/curl-8_4_0/curl-8.4.0.tar.xz
                           URL_HASH               SHA256=16c62a9c4af0f703d28bda6d7bbf37ba47055ad3414d70dec63e2e6336f2a82d # the file hash for curl-8.4.0.tar.xz
                           USES_TERMINAL_DOWNLOAD TRUE)   # <---- This is needed only for Ninja to show download progress
      FetchContent_MakeAvailable(curl)

    endif()
  endif()

  file(GLOB cpr_sources ${conf_depends} cpr/cpr/*.cpp)

  add_library(cpr STATIC EXCLUDE_FROM_ALL ${cpr_sources})
  target_link_libraries(cpr PUBLIC CURL::libcurl)
  target_include_directories(cpr PUBLIC cpr/include)
  target_compile_definitions(cpr PUBLIC CPR_CURL_NOSIGNAL)
  add_library(cpr::cpr ALIAS cpr)

  file(READ cpr/CMakeLists.txt cpr_cmake_head LIMIT 1000)
  if(cpr_cmake_head MATCHES "project\\(cpr VERSION ([0-9]+)\.([0-9]+)\.([0-9]+) LANGUAGES CXX\\)")
    set(cpr_VERSION_MAJOR ${CMAKE_MATCH_1})
    set(cpr_VERSION_MINOR ${CMAKE_MATCH_2})
    set(cpr_VERSION_PATCH ${CMAKE_MATCH_3})
    set(cpr_VERSION "${cpr_VERSION_MAJOR}.${cpr_VERSION_MINOR}.${cpr_VERSION_PATCH}")
    set(cpr_VERSION_NUM "(${cpr_VERSION_MAJOR} * 0x10000 + ${cpr_VERSION_MINOR} * 0x100 + ${cpr_VERSION_PATCH})")

    configure_file(cpr/cmake/cprver.h.in "${CMAKE_CURRENT_BINARY_DIR}/cpr_generated_includes/cpr/cprver.h")
    target_include_directories(cpr PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/cpr_generated_includes")
  else()
    message(FATAL_ERROR "Could not identify cpr submodule version!")
  endif()

endif()


# libcrypt defaults, only on with macos and non static linux
set(default_libcrypt OFF)

if(LINUX AND NOT STATIC_LINK)
  pkg_check_modules(LIBCRYPT libcrypt IMPORTED_TARGET)
  if(LIBCRYPTO_FOUND)
      set(default_libcrypt ON)
  endif()
endif()
if(MACOS)
  set(default_libcrypt ON)
endif()

option(WITH_LIBCRYPT "enable fast password hash with libcrypt" ${default_libcrypt})

add_library(lokinet-libcrypt INTERFACE)
if(WITH_LIBCRYPT)
  pkg_check_modules(LIBCRYPT libcrypt IMPORTED_TARGET REQUIRED)
  target_compile_definitions(lokinet-libcrypt INTERFACE -DHAVE_CRYPT)
  target_link_libraries(lokinet-libcrypt INTERFACE PkgConfig::LIBCRYPT)
  message(STATUS "using libcrypt ${LIBCRYPT_VERSION}")
else()
  # TODO static build lib crypt?
  message(STATUS "not building with libcrypt")
endif()
