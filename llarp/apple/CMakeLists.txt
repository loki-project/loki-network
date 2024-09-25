
# 3.13+ so that we can add link libraries to parent targets
cmake_minimum_required(VERSION 3.13)

if (BUILD_SHARED_LIBS OR NOT BUILD_STATIC_DEPS OR NOT STATIC_LINK)
  message(FATAL_ERROR "macOS builds require a full static build; perhaps use the contrib/mac.sh script to build?")
endif()

# god (steve jobs) made apple so that man may suffer
find_library(FOUNDATION Foundation REQUIRED)
find_library(NETEXT NetworkExtension REQUIRED)
find_library(COREFOUNDATION CoreFoundation REQUIRED)

target_link_libraries(lokinet-base INTERFACE ${FOUNDATION})

target_sources(lokinet-platform PRIVATE vpn_platform.cpp vpn_interface.cpp route_manager.cpp context_wrapper.cpp)

add_executable(lokinet-extension MACOSX_BUNDLE
  PacketTunnelProvider.m
  DNSTrampoline.m
)

enable_lto(lokinet-extension)

# -fobjc-arc enables automatic reference counting for objective-C code
# -e _NSExtensionMain because the appex has that instead of a `main` function entry point, of course.
target_compile_options(lokinet-extension PRIVATE -fobjc-arc)
if(MACOS_SYSTEM_EXTENSION)
  target_compile_definitions(lokinet-extension PRIVATE MACOS_SYSTEM_EXTENSION)
  target_compile_definitions(lokinet-base INTERFACE MACOS_SYSTEM_EXTENSION)
else()
  target_link_options(lokinet-extension PRIVATE -e _NSExtensionMain)
endif()

if(MACOS_SYSTEM_EXTENSION)
    set(bundle_ext systemextension)
    set(product_type com.apple.product-type.system-extension)
else()
    set(bundle_ext appex)
    set(product_type com.apple.product-type.app-extension)
endif()

target_link_libraries(lokinet-extension PRIVATE
  lokinet-core
  ${COREFOUNDATION}
  ${NETEXT})

set_target_properties(lokinet-extension PROPERTIES
  BUNDLE TRUE
  BUNDLE_EXTENSION ${bundle_ext}
  OUTPUT_NAME org.lokinet.network-extension
  MACOSX_BUNDLE_INFO_PLIST ${PROJECT_SOURCE_DIR}/contrib/macos/lokinet-extension.Info.plist.in
  XCODE_PRODUCT_TYPE ${product_type}
  )

if(CODESIGN AND CODESIGN_EXT_PROFILE)
  add_custom_command(TARGET lokinet-extension
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      ${CODESIGN_EXT_PROFILE}
      $<TARGET_BUNDLE_DIR:lokinet-extension>/Contents/embedded.provisionprofile
  )
endif()
