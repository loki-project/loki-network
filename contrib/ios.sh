#!/bin/bash
#
# Build the shit for iphone, only builds embeded lokinet

set -e
set -x
if ! [ -f LICENSE ] || ! [ -d llarp ]; then
    echo "You need to run this as ./contrib/ios.sh from the top-level lokinet project directory"
fi

_sdk=${SDK:-iphoneos}

mkdir -p build/iphone
cmake \
    -G Ninja \
    -DWITH_CCACHE=OFF \
    -DCMAKE_C_COMPILER=$(xcrun --find --sdk ${_sdk} clang ) \
    -DCMAKE_CXX_COMPILER=$(xcrun --find --sdk ${_sdk} clang++ ) \
    -DCMAKE_OSX_SYSROOT=$( xcrun --sdk ${_sdk} --show-sdk-path ) \
    -DCMAKE_TOOLCHAIN_FILE=contrib/cross/ios.toolchain.cmake \
    -DBUILD_STATIC_DEPS=ON \
    -DBUILD_PACKAGE=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=OFF \
    -DBUILD_LIBLOKINET=ON \
    -DWITH_TESTS=OFF \
    -DNATIVE_BUILD=OFF \
    -DSTATIC_LINK=ON \
    -DWITH_SYSTEMD=OFF \
    -DWITH_BOOTSTRAP=OFF \
    -DBUILD_DAEMON=OFF \
    -DFORCE_OXENMQ_SUBMODULE=ON \
    -DFORCE_OXENC_SUBMODULE=ON \
    -DFORCE_NLOHMANN_SUBMODULE=ON \
    -DSUBMODULE_CHECK=ON \
    -DWITH_LTO=OFF \
    -S . -B build/iphone \
    "$@"

cmake --build build/iphone --target lokinet-shared