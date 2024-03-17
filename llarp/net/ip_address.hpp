#pragma once

#include "net_int.hpp"
#include "sock_addr.hpp"

#include <llarp/util/formattable.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace llarp
{
    /// A struct that can represent either an IPv4 or IPv6 address. It is meant for representation
    /// purposes only (e.g. serialization/deserialization). In addition, it also optionally stores
    /// a port.
    ///
    /// As a convenience, it can produce a SockAddr for dealing with network libraries which depend
    /// sockaddr structs. However, it does not keep this as a member variable and isn't responsible
    /// for its lifetime/memory/etc.
    struct /* [[deprecated("use llarp::SockAddr instead")]] */ Ip_address_deprecated
    {
        /// Empty constructor.
        Ip_address_deprecated() = default;
        /// move construtor
        Ip_address_deprecated(Ip_address_deprecated&&) = default;
        /// copy construct
        Ip_address_deprecated(const Ip_address_deprecated&);

        /// Constructor. Takes a string which can be an IPv4 or IPv6 address optionally followed by
        /// a colon and a port.
        ///
        /// Examples:
        ///
        /// 127.0.0.1
        /// 1.2.3.4:53
        ///
        /// Note that an IPv6 + port representation must be done in an unambiguous way, e.g. wrap
        /// the IP portion of the string in brackets: [IPv6Addr]:port
        ///
        /// @param str is a string representing an IP address and optionally a port
        /// @throws std::invalid_argument if str cannot be parsed
        Ip_address_deprecated(std::string_view str);

        /// Constructor. Takes an IP address (as above) and a port. The string may not contain a
        /// port.
        ///
        /// @param str is a string representing an IP address and optionally a port
        /// @throws std::invalid_argument if str cannot be parsed
        Ip_address_deprecated(std::string_view str, std::optional<uint16_t> port);

        /// Construct from a SockAddr.
        ///
        /// @param addr is an SockAddr to initialize from.
        Ip_address_deprecated(const SockAddr_deprecated& addr);

        Ip_address_deprecated& operator=(const sockaddr& other);

        /// move assignment
        Ip_address_deprecated& operator=(Ip_address_deprecated&& other);

        /// copy assignment
        Ip_address_deprecated& operator=(const Ip_address_deprecated& other);

        /// Return the port. Returns -1 if no port has been provided.
        ///
        /// @return the port, if present
        std::optional<uint16_t> getPort() const;

        /// Return true if we have a port set otherwise return false
        bool hasPort() const;

        /// Set the port.
        ///
        /// @param port
        void setPort(std::optional<uint16_t> port);

        /// Set the IP address. Follows the same logic as the constructor with the same signature,
        /// but doesn't overwrite the port if the port isn't present in the string.
        void setAddress(std::string_view str);
        void setAddress(std::string_view str, std::optional<uint16_t> port);

        /// Returns true if this is an IPv4 address (or an IPv6 address representing an IPv4
        /// address)
        ///
        /// TODO: could return an int (e.g. 4 or 6) or an enum
        ///
        /// @return true if this is an IPv4 address, false otherwise
        bool isIPv4();

        /// Returns true if this represents a valid IpAddress, false otherwise.
        ///
        /// @return whether or not this IpAddress is empty
        bool isEmpty() const;

        /// Creates an instance of SockAddr representing this IpAddress.
        ///
        /// @return an instance of a SockAddr created from this IpAddress
        SockAddr_deprecated createSockAddr() const;

        /// Returns true if this IpAddress is a bogon, false otherwise
        ///
        /// @return whether or not this IpAddress is a bogon
        bool isBogon() const;

        /// Returns a string representing this IpAddress
        ///
        /// @return string representation of this IpAddress
        std::string to_string() const;

        std::string toHost() const;

        huint32_t toIP() const;

        huint128_t toIP6() const;

        // TODO: other utility functions left over from Addr which may be useful
        // IsBogon() const;
        // isPrivate() const;
        // std::hash
        // to string / stream / etc

        bool operator<(const Ip_address_deprecated& other) const;

        bool operator==(const Ip_address_deprecated& other) const;

      private:
        bool m_empty = true;
        std::string m_ipAddress;
        std::optional<uint16_t> m_port = std::nullopt;
    };

    template <>
    inline constexpr bool IsToStringFormattable<Ip_address_deprecated> = true;

}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::Ip_address_deprecated>
    {
        std::size_t operator()(const llarp::Ip_address_deprecated& address) const noexcept
        {
            return std::hash<std::string>{}(address.to_string());
        }
    };
}  // namespace std
