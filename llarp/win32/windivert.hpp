#pragma once
#include <llarp/vpn/packet_io.hpp>

#include <windows.h>

#include <memory>
#include <string>

namespace llarp::win32::WinDivert
{
    /// format an ipv4 in host order to string such that a windivert filter spec can understand it
    std::string format_ip(uint32_t ip);

    /// create a packet interceptor that uses windivert.
    /// filter_spec describes the kind of traffic we wish to intercept.
    /// pass in a callable that wakes up the main event loop.
    /// we hide all implementation details from other compilation units to prevent issues with
    /// linkage that may arrise.
    std::shared_ptr<llarp::vpn::PacketIO> make_interceptor(
        const std::string& filter_spec, std::function<void(void)> wakeup);

}  // namespace llarp::win32::WinDivert
