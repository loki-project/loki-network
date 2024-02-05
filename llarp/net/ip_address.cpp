#include "ip_address.hpp"

#include "ip_range.hpp"

namespace llarp
{
    IpAddress::IpAddress(std::string_view str)
    {
        setAddress(str);
    }

    IpAddress::IpAddress(const IpAddress& other)
        : m_empty(other.m_empty), m_ipAddress(other.m_ipAddress), m_port(other.m_port)
    {}

    IpAddress::IpAddress(std::string_view str, std::optional<uint16_t> port)
    {
        setAddress(str, port);
    }

    IpAddress::IpAddress(const SockAddr& addr)
    {
        m_ipAddress = addr.to_string();
        uint16_t port = addr.getPort();
        if (port > 0)
            m_port = port;

        m_empty = addr.isEmpty();
    }

    IpAddress& IpAddress::operator=(IpAddress&& other)
    {
        m_ipAddress = std::move(other.m_ipAddress);
        m_port = std::move(other.m_port);
        m_empty = other.m_empty;
        other.m_empty = false;
        return *this;
    }

    IpAddress& IpAddress::operator=(const sockaddr& other)
    {
        SockAddr addr(other);

        m_ipAddress = addr.to_string();
        uint16_t port = addr.getPort();
        if (port > 0)
            m_port = port;

        m_empty = addr.isEmpty();

        return *this;
    }
    IpAddress& IpAddress::operator=(const IpAddress& other)
    {
        m_empty = other.m_empty;
        m_ipAddress = other.m_ipAddress;
        m_port = other.m_port;
        return *this;
    }

    std::optional<uint16_t> IpAddress::getPort() const
    {
        return m_port;
    }

    void IpAddress::setPort(std::optional<uint16_t> port)
    {
        m_port = port;
    }

    void IpAddress::setAddress(std::string_view str)
    {
        SockAddr addr;
        addr.fromString(str);

        m_ipAddress = std::string(str);
        uint16_t port = addr.getPort();
        if (port > 0)
            m_port = port;

        m_empty = addr.isEmpty();
    }

    void IpAddress::setAddress(std::string_view str, std::optional<uint16_t> port)
    {
        SockAddr addr;
        addr.fromString(str);

        m_ipAddress = std::string(str);
        m_port = port;

        m_empty = addr.isEmpty();
    }

    bool IpAddress::isIPv4()
    {
        throw std::runtime_error("FIXME - IpAddress::isIPv4()");
    }

    bool IpAddress::isEmpty() const
    {
        return m_empty;
    }

    SockAddr IpAddress::createSockAddr() const
    {
        SockAddr addr(m_ipAddress);
        if (m_port)
            addr.setPort(*m_port);

        return addr;
    }

    bool IpAddress::isBogon() const
    {
        SockAddr addr(m_ipAddress);
        const auto* addr6 = static_cast<const sockaddr_in6*>(addr);
        const uint8_t* raw = addr6->sin6_addr.s6_addr;
        return IPRange::V4MappedRange().Contains(ipaddr_ipv4_bits(raw[12], raw[13], raw[14], raw[15]));
    }

    std::string IpAddress::to_string() const
    {
        return m_ipAddress;  // TODO: port
    }

    bool IpAddress::hasPort() const
    {
        return m_port.has_value();
    }

    std::string IpAddress::toHost() const
    {
        const auto pos = m_ipAddress.find(":");
        if (pos != std::string::npos)
        {
            return m_ipAddress.substr(0, pos);
        }
        return m_ipAddress;
    }

    huint32_t IpAddress::toIP() const
    {
        huint32_t ip;
        ip.FromString(toHost());
        return ip;
    }

    huint128_t IpAddress::toIP6() const
    {
        huint128_t ip;
        ip.FromString(m_ipAddress);
        return ip;
    }

    bool IpAddress::operator<(const IpAddress& other) const
    {
        return createSockAddr() < other.createSockAddr();
    }

    bool IpAddress::operator==(const IpAddress& other) const
    {
        return createSockAddr() == other.createSockAddr();
    }
}  // namespace llarp
