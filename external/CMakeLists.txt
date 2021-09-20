
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
    endfunction ()

    message(STATUS "Checking submodules")
    check_submodule(nlohmann)
    check_submodule(cxxopts)
    check_submodule(ghc-filesystem)
    check_submodule(date)
    check_submodule(pybind11)
    check_submodule(sqlite_orm)
    check_submodule(oxen-mq)
    check_submodule(uvw)
    check_submodule(cpr)
    check_submodule(ngtcp2)
  endif()
endif()

if(WITH_HIVE)
  add_subdirectory(pybind11 EXCLUDE_FROM_ALL)
endif()

set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(nlohmann EXCLUDE_FROM_ALL)
add_subdirectory(cxxopts EXCLUDE_FROM_ALL)
add_subdirectory(date EXCLUDE_FROM_ALL)

add_library(sqlite_orm INTERFACE)
target_include_directories(sqlite_orm SYSTEM INTERFACE sqlite_orm/include)
if(NOT TARGET sqlite3)
  add_library(sqlite3 INTERFACE)
  pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
  target_link_libraries(sqlite3 INTERFACE PkgConfig::SQLITE3)
endif()
target_link_libraries(sqlite_orm INTERFACE sqlite3)

add_library(uvw INTERFACE)
target_include_directories(uvw INTERFACE uvw/src)
target_link_libraries(uvw INTERFACE libuv)

# ngtcp2 needs some massaging to build nicely:
include(ngtcp2_lib)
add_ngtcp2_lib()

# cpr configuration.  Ideally we'd just do this via add_subdirectory, but cpr's cmake requires
# 3.15+, and we target lower than that (and this is fairly simple to build).
if(WITH_BOOTSTRAP)
if(NOT BUILD_STATIC_DEPS)
  find_package(CURL REQUIRED COMPONENTS HTTP HTTPS SSL)

  # CURL::libcurl wasn't added to FindCURL until cmake 3.12, so add it if necessary
  if (CMAKE_VERSION VERSION_LESS 3.12 AND NOT TARGET CURL::libcurl)
    add_library(libcurl UNKNOWN IMPORTED GLOBAL)
    set_target_properties(libcurl PROPERTIES
      IMPORTED_LOCATION ${CURL_LIBRARIES}
      INTERFACE_INCLUDE_DIRECTORIES "${CURL_INCLUDE_DIRS}")
    add_library(CURL_libcurl INTERFACE)
    target_link_libraries(CURL_libcurl INTERFACE libcurl)
    add_library(CURL::libcurl ALIAS CURL_libcurl)
  endif()
endif()

file(GLOB cpr_sources ${conf_depends} cpr/cpr/*.cpp)

add_library(cpr STATIC EXCLUDE_FROM_ALL ${cpr_sources})
target_link_libraries(cpr PUBLIC CURL::libcurl)
target_include_directories(cpr PUBLIC cpr/include)
target_compile_definitions(cpr PUBLIC CPR_CURL_NOSIGNAL)
add_library(cpr::cpr ALIAS cpr)
endif()
