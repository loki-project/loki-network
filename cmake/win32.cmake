if(NOT WIN32)
  return()
endif()
if (NOT STATIC_LINK)
  message(FATAL_ERROR "windows requires static builds (thanks balmer)")
endif()

enable_language(RC)

option(WITH_WINDOWS_32 "build 32 bit windows" OFF)

# unlike unix where you get a *single* compiler ID string in .comment
# GNU ld sees fit to merge *all* the .ident sections in object files
# to .r[o]data section one after the other!
add_compile_options(-fno-ident -Wa,-mbig-obj)

function(expand_urls output source_file)
  set(expanded)
  foreach(mirror ${ARGN})
    list(APPEND expanded "${mirror}/${source_file}")
  endforeach()
  set(${output} "${expanded}" PARENT_SCOPE)
endfunction()

function(add_static_target target ext_target libname)
  add_library(${target} STATIC IMPORTED GLOBAL)
  add_dependencies(${target} ${ext_target})
  set_target_properties(${target} PROPERTIES
    IMPORTED_LOCATION ${DEPS_DESTDIR}/lib/${libname}
  )
endfunction()

if(EMBEDDED_CFG)
  link_libatomic()
endif()

set(WINTUN_VERSION 0.14.1 CACHE STRING "wintun version")
set(WINTUN_MIRROR ${LOCAL_MIRROR} https://www.wintun.net/builds
  CACHE STRING "wintun mirror(s)")
set(WINTUN_SOURCE wintun-${WINTUN_VERSION}.zip)
set(WINTUN_HASH SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
  CACHE STRING "wintun source hash")

set(WINDIVERT_VERSION 2.2.2-A CACHE STRING "windivert version")
set(WINDIVERT_MIRROR ${LOCAL_MIRROR} https://reqrypt.org/download
  CACHE STRING "windivert mirror(s)")
set(WINDIVERT_SOURCE WinDivert-${WINDIVERT_VERSION}.zip)
set(WINDIVERT_HASH SHA512=92eb2ef98ced175d44de1cdb7c52f2ebc534b6a997926baeb83bfe94cba9287b438f796aff11f6163918bcdbc25bcd4e3383715f139f690d207ce219f846a345
  CACHE STRING "windivert source hash")

expand_urls(WINTUN_URL ${WINTUN_SOURCE} ${WINTUN_MIRROR})
expand_urls(WINDIVERT_URL ${WINDIVERT_SOURCE} ${WINDIVERT_MIRROR})

message(STATUS "Downloading wintun from ${WINTUN_URL}")
file(DOWNLOAD ${WINTUN_URL} ${CMAKE_BINARY_DIR}/wintun.zip EXPECTED_HASH ${WINTUN_HASH})
message(STATUS "Downloading windivert from ${WINDIVERT_URL}")
file(DOWNLOAD ${WINDIVERT_URL} ${CMAKE_BINARY_DIR}/windivert.zip EXPECTED_HASH ${WINDIVERT_HASH})

execute_process(COMMAND ${CMAKE_COMMAND} -E tar x ${CMAKE_BINARY_DIR}/wintun.zip
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

execute_process(COMMAND ${CMAKE_COMMAND} -E tar x ${CMAKE_BINARY_DIR}/windivert.zip
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
