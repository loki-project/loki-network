#pragma once

#include <llarp/address/ip_range.hpp>
#include <llarp/util/formattable.hpp>

#include <optional>
#include <string>
#include <vector>

namespace llarp::net
{
    /// info about a network interface lokinet does not own
    struct InterfaceInfo
    {
      private:
      public:
        // TODO: is this needed?
        /// a gateway we can use if it exists
        std::optional<ip_net> _gateway;

        /// human readable name of interface
        std::string name;
        /// interface's index
        int index;
        /// the addresses owned by this interface
        std::vector<IPRange> addrs;

        std::string to_string() const;
    };
}  // namespace llarp::net

template <>
inline constexpr bool llarp::IsToStringFormattable<llarp::net::InterfaceInfo> = true;
