#pragma once

/// namespace for platform feature detection constexprs
namespace llarp::platform
{
    ///  are we linux  ?
    inline constexpr bool is_linux =
#ifdef __linux__
        true
#else
        false
#endif
        ;

    /// building with systemd enabled ?
    inline constexpr bool with_systemd =
#ifdef WITH_SYSTEMD
        true
#else
        false
#endif
        ;

    ///  are we freebsd ?
    inline constexpr bool is_freebsd =
#ifdef __FreeBSD__
        true
#else
        false
#endif
        ;

    /// are we windows ?
    inline constexpr bool is_windows =
#ifdef _WIN32
        true
#else
        false
#endif
        ;

    /// are we an apple platform ?
    inline constexpr bool is_apple =
#ifdef __APPLE__
        true
#else
        false
#endif
        ;

    /// are we building as an apple system extension
    inline constexpr bool is_apple_sysex =
#ifdef MACOS_SYSTEM_EXTENSION
        true
#else
        false
#endif
        ;

    /// are we an android platform ?
    inline constexpr bool is_android =
#ifdef ANDROID
        true
#else
        false
#endif
        ;

    /// are we an iphone ?
    inline constexpr bool is_iphone =
#ifdef IOS
        true
#else
        false
#endif
        ;

    /// are we running with pybind simulation mode enabled?
    inline constexpr bool is_simulation =
#ifdef LOKINET_HIVE
        true
#else
        false
#endif
        ;
    /// do we have systemd support ?
    // on cross compiles sometimes weird permutations of target and host make this value not
    // correct, this ensures it always is
    inline constexpr bool has_systemd = is_linux and with_systemd and not(is_android or is_windows);

    /// are we using macos ?
    inline constexpr bool is_macos = is_apple and not is_iphone;

    /// are we a mobile phone ?
    inline constexpr bool is_mobile = is_android or is_iphone;

    /// does this platform support native ipv6 ?
    // TODO: make windows support ipv6
    inline constexpr bool supports_ipv6 = not is_windows;
}  // namespace llarp::platform
