#include "ip_address.hpp"

#include "ip_range.hpp"

namespace llarp
{
    Ip_address_deprecated::Ip_address_deprecated(std::string_view str)
    {
        setAddress(str);
    }

    Ip_address_deprecated::Ip_address_deprecated(const Ip_address_deprecated& other)
        : m_empty(other.m_empty), m_ipAddress(other.m_ipAddress), m_port(other.m_port)
    {}

    Ip_address_deprecated::Ip_address_deprecated(std::string_view str, std::optional<uint16_t> port)
    {
        setAddress(str, port);
    }

    Ip_address_deprecated::Ip_address_deprecated(const SockAddr_deprecated& addr)
    {
        m_ipAddress = addr.to_string();
        uint16_t port = addr.getPort();
        if (port > 0)
            m_port = port;

        m_empty = addr.isEmpty();
    }

    Ip_address_deprecated& Ip_address_deprecated::operator=(Ip_address_deprecated&& other)
    {
        m_ipAddress = std::move(other.m_ipAddress);
        m_port = std::move(other.m_port);
        m_empty = other.m_empty;
        other.m_empty = false;
        return *this;
    }

    Ip_address_deprecated& Ip_address_deprecated::operator=(const sockaddr& other)
    {
        SockAddr_deprecated addr(other);

        m_ipAddress = addr.to_string();
        uint16_t port = addr.getPort();
        if (port > 0)
            m_port = port;

        m_empty = addr.isEmpty();

        return *this;
    }
    Ip_address_deprecated& Ip_address_deprecated::operator=(const Ip_address_deprecated& other)
    {
        m_empty = other.m_empty;
        m_ipAddress = other.m_ipAddress;
        m_port = other.m_port;
        return *this;
    }

    std::optional<uint16_t> Ip_address_deprecated::getPort() const
    {
        return m_port;
    }

    void Ip_address_deprecated::setPort(std::optional<uint16_t> port)
    {
        m_port = port;
    }

    void Ip_address_deprecated::setAddress(std::string_view str)
    {
        SockAddr_deprecated addr;
        addr.fromString(str);

        m_ipAddress = std::string(str);
        uint16_t port = addr.getPort();
        if (port > 0)
            m_port = port;

        m_empty = addr.isEmpty();
    }

    void Ip_address_deprecated::setAddress(std::string_view str, std::optional<uint16_t> port)
    {
        SockAddr_deprecated addr;
        addr.fromString(str);

        m_ipAddress = std::string(str);
        m_port = port;

        m_empty = addr.isEmpty();
    }

    bool Ip_address_deprecated::isIPv4()
    {
        throw std::runtime_error("FIXME - IpAddress::isIPv4()");
    }

    bool Ip_address_deprecated::isEmpty() const
    {
        return m_empty;
    }

    SockAddr_deprecated Ip_address_deprecated::createSockAddr() const
    {
        SockAddr_deprecated addr(m_ipAddress);
        if (m_port)
            addr.setPort(*m_port);

        return addr;
    }

    bool Ip_address_deprecated::isBogon() const
    {
        SockAddr_deprecated addr(m_ipAddress);
        const auto* addr6 = static_cast<const sockaddr_in6*>(addr);
        const uint8_t* raw = addr6->sin6_addr.s6_addr;
        return IP_range_deprecated::V4MappedRange().Contains(ipaddr_ipv4_bits(raw[12], raw[13], raw[14], raw[15]));
    }

    std::string Ip_address_deprecated::to_string() const
    {
        return m_ipAddress;  // TODO: port
    }

    bool Ip_address_deprecated::hasPort() const
    {
        return m_port.has_value();
    }

    std::string Ip_address_deprecated::toHost() const
    {
        const auto pos = m_ipAddress.find(":");
        if (pos != std::string::npos)
        {
            return m_ipAddress.substr(0, pos);
        }
        return m_ipAddress;
    }

    huint32_t Ip_address_deprecated::toIP() const
    {
        huint32_t ip;
        ip.FromString(toHost());
        return ip;
    }

    huint128_t Ip_address_deprecated::toIP6() const
    {
        huint128_t ip;
        ip.FromString(m_ipAddress);
        return ip;
    }

    bool Ip_address_deprecated::operator<(const Ip_address_deprecated& other) const
    {
        return createSockAddr() < other.createSockAddr();
    }

    bool Ip_address_deprecated::operator==(const Ip_address_deprecated& other) const
    {
        return createSockAddr() == other.createSockAddr();
    }
}  // namespace llarp
