#include "sock_addr.hpp"

#include "ip.hpp"
#include "ip_range.hpp"
#include "net.hpp"
#include "net_bits.hpp"

#include <llarp/util/mem.hpp>
#include <llarp/util/str.hpp>

#include <stdexcept>

namespace llarp
{
    /// shared utility functions
    ///

    void SockAddr_deprecated::init()
    {
        llarp::Zero(&addr6, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        llarp::Zero(&addr4, sizeof(addr4));
        addr4.sin_family = AF_INET;
    }

    void SockAddr_deprecated::applyIPv4MapBytes()
    {
        std::memcpy(addr6.sin6_addr.s6_addr, ipv4_map_prefix.data(), ipv4_map_prefix.size());
    }

    SockAddr_deprecated::SockAddr_deprecated()
    {
        init();
    }

    SockAddr_deprecated::SockAddr_deprecated(uint8_t a, uint8_t b, uint8_t c, uint8_t d, huint16_t port)
    {
        init();
        setIPv4(a, b, c, d);
        setPort(port);
    }

    SockAddr_deprecated::SockAddr_deprecated(nuint32_t ip, nuint16_t port)
    {
        init();
        setIPv4(ip);
        setPort(port);
    }

    SockAddr_deprecated::SockAddr_deprecated(huint32_t ip, huint16_t port) : SockAddr_deprecated{ToNet(ip), ToNet(port)}
    {}

    SockAddr_deprecated::SockAddr_deprecated(huint128_t ip, huint16_t port)
    {
        init();
        setIPv6(ip);
        setPort(port);
    }

    SockAddr_deprecated::SockAddr_deprecated(nuint128_t ip, nuint16_t port)
    {
        init();
        setIPv6(ip);
        setPort(port);
    }

    SockAddr_deprecated::SockAddr_deprecated(std::string_view addr)
    {
        init();
        fromString(addr);
    }
    SockAddr_deprecated::SockAddr_deprecated(std::string_view addr, huint16_t port)
    {
        init();
        setPort(port);
        fromString(addr, false);
    }

    SockAddr_deprecated::SockAddr_deprecated(const SockAddr_deprecated& other)
    {
        *this = other;
    }

    SockAddr_deprecated& SockAddr_deprecated::operator=(const SockAddr_deprecated& other)
    {
        *this = other.addr6;
        return *this;
    }

    SockAddr_deprecated::SockAddr_deprecated(const sockaddr& addr)
    {
        *this = addr;
    }

    SockAddr_deprecated& SockAddr_deprecated::operator=(const sockaddr& other)
    {
        if (other.sa_family == AF_INET6)
            *this = reinterpret_cast<const sockaddr_in6&>(other);
        else if (other.sa_family == AF_INET)
            *this = reinterpret_cast<const sockaddr_in&>(other);
        else
            throw std::invalid_argument{
                fmt::format("Invalid sockaddr (not AF_INET or AF_INET6) was {}", other.sa_family)};

        return *this;
    }

    SockAddr_deprecated::SockAddr_deprecated(const sockaddr_in& addr)
    {
        *this = addr;
    }

    SockAddr_deprecated& SockAddr_deprecated::operator=(const sockaddr_in& other)
    {
        init();
        applyIPv4MapBytes();

        // avoid byte order conversion (this is NBO -> NBO)
        memcpy(addr6.sin6_addr.s6_addr + 12, &other.sin_addr.s_addr, sizeof(in_addr));
        addr6.sin6_port = other.sin_port;
        addr4.sin_addr.s_addr = other.sin_addr.s_addr;
        addr4.sin_port = other.sin_port;
        m_empty = false;

        return *this;
    }

    SockAddr_deprecated::SockAddr_deprecated(const sockaddr_in6& addr)
    {
        *this = addr;
    }

    SockAddr_deprecated& SockAddr_deprecated::operator=(const sockaddr_in6& other)
    {
        init();

        memcpy(&addr6, &other, sizeof(sockaddr_in6));
        if (IP_range_deprecated::V4MappedRange().Contains(asIPv6()))
        {
            setIPv4(
                other.sin6_addr.s6_addr[12],
                other.sin6_addr.s6_addr[13],
                other.sin6_addr.s6_addr[14],
                other.sin6_addr.s6_addr[15]);
            addr4.sin_port = addr6.sin6_port;
        }
        m_empty = false;

        return *this;
    }

    SockAddr_deprecated::SockAddr_deprecated(const in6_addr& addr)
    {
        *this = addr;
    }

    SockAddr_deprecated& SockAddr_deprecated::operator=(const in6_addr& other)
    {
        init();
        memcpy(&addr6.sin6_addr.s6_addr, &other.s6_addr, sizeof(addr6.sin6_addr.s6_addr));
        if (IP_range_deprecated::V4MappedRange().Contains(asIPv6()))
        {
            setIPv4(other.s6_addr[12], other.s6_addr[13], other.s6_addr[14], other.s6_addr[15]);
            addr4.sin_port = addr6.sin6_port;
        }
        m_empty = false;

        return *this;
    }

    SockAddr_deprecated::operator const sockaddr*() const
    {
        return isIPv4() ? reinterpret_cast<const sockaddr*>(&addr4) : reinterpret_cast<const sockaddr*>(&addr6);
    }

    SockAddr_deprecated::operator const sockaddr_in*() const
    {
        return &addr4;
    }

    SockAddr_deprecated::operator const sockaddr_in6*() const
    {
        return &addr6;
    }

    size_t SockAddr_deprecated::sockaddr_len() const
    {
        return isIPv6() ? sizeof(addr6) : sizeof(addr4);
    }

    bool SockAddr_deprecated::operator<(const SockAddr_deprecated& other) const
    {
        return addr6 < other.addr6;
    }

    bool SockAddr_deprecated::operator==(const SockAddr_deprecated& other) const
    {
        return addr6 == other.addr6;
    }

    huint128_t SockAddr_deprecated::asIPv6() const
    {
        return net::In6ToHUInt(addr6.sin6_addr);
    }

    huint32_t SockAddr_deprecated::asIPv4() const
    {
        const nuint32_t n{addr4.sin_addr.s_addr};
        return ToHost(n);
    }

    void SockAddr_deprecated::fromString(std::string_view str, bool allow_port)
    {
        if (str.empty())
        {
            init();
            m_empty = true;
            return;
        }

        // TOFIX: This potentially involves multiple memory allocations,
        // reimplement without split() if it is performance bottleneck
        auto splits = split(str, ":");

        // TODO: having ":port" at the end makes this ambiguous with IPv6
        //       come up with a strategy for implementing
        if (splits.size() > 2)
        {
            std::string data{str};
            if (inet_pton(AF_INET6, data.c_str(), addr6.sin6_addr.s6_addr) == -1)
                throw std::runtime_error{"invalid ip6 address: " + data};
            return;
        }

        // split() shouldn't return an empty list if str is empty (checked above)
        assert(splits.size() > 0);

        // splits[0] should be dot-separated IPv4
        auto ipSplits = split(splits[0], ".");
        if (ipSplits.size() != 4)
            throw std::invalid_argument(fmt::format("{} is not a valid IPv4 address", str));

        std::array<uint8_t, 4> ipBytes;
        for (int i = 0; i < 4; ++i)
            if (not parse_int(ipSplits[i], ipBytes[i]))
                throw std::runtime_error(fmt::format("{} contains invalid numeric value", str));

        // attempt port before setting IPv4 bytes
        if (splits.size() == 2)
        {
            if (not allow_port)
                throw std::runtime_error{fmt::format("invalid ip address (port not allowed here): {}", str)};
            uint16_t port;
            if (not parse_int(splits[1], port))
                throw std::runtime_error{fmt::format("{} is not a valid port", splits[1])};
            setPort(port);
        }

        setIPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]);
    }

    std::string SockAddr_deprecated::to_string() const
    {
        // TODO: review
        if (isEmpty())
            return "";
        return fmt::format("{}:{}", hostString(), port());
    }

    std::string SockAddr_deprecated::hostString(bool ipv6_brackets) const
    {
        std::array<char, 128> buf{};
        if (isIPv4())
        {
            // IPv4 mapped addrs
            inet_ntop(AF_INET, &addr4.sin_addr.s_addr, buf.data(), buf.size());
            return buf.data();
        }

        inet_ntop(AF_INET6, &addr6.sin6_addr.s6_addr, buf.data(), buf.size());
        if (not ipv6_brackets)
            return buf.data();

        return fmt::format("[{}]", buf.data());
    }

    bool SockAddr_deprecated::isEmpty() const
    {
        return m_empty;
    }

    bool SockAddr_deprecated::isIPv4() const
    {
        return IP_range_deprecated::V4MappedRange().Contains(asIPv6());
    }
    bool SockAddr_deprecated::isIPv6() const
    {
        return not isIPv4();
    }

    nuint32_t SockAddr_deprecated::getIPv4() const
    {
        return {addr4.sin_addr.s_addr};
    }

    nuint128_t SockAddr_deprecated::getIPv6() const
    {
        nuint128_t a;
        // Explicit cast to void* here to avoid non-trivial type copying warnings (technically this
        // isn't trivial because of the zeroing default constructor, but it's trivial enough that
        // this copy is safe).
        std::memcpy(static_cast<void*>(&a), &addr6.sin6_addr, 16);
        return a;
    }

    std::variant<nuint32_t, nuint128_t> SockAddr_deprecated::getIP() const
    {
        if (isIPv4())
            return getIPv4();
        return getIPv6();
    }

    void SockAddr_deprecated::setIPv4(nuint32_t ip)
    {
        uint8_t* ip6 = addr6.sin6_addr.s6_addr;
        llarp::Zero(ip6, sizeof(addr6.sin6_addr.s6_addr));

        applyIPv4MapBytes();

        std::memcpy(ip6 + 12, &ip, 4);
        addr4.sin_addr.s_addr = ip.n;
        m_empty = false;
    }

    void SockAddr_deprecated::setIPv4(huint32_t ip)
    {
        setIPv4(ToNet(ip));
    }

    void SockAddr_deprecated::setIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
    {
        uint8_t* ip6 = addr6.sin6_addr.s6_addr;
        llarp::Zero(ip6, sizeof(addr6.sin6_addr.s6_addr));

        applyIPv4MapBytes();

        ip6[12] = a;
        ip6[13] = b;
        ip6[14] = c;
        ip6[15] = d;
        const auto ip = ipaddr_ipv4_bits(a, b, c, d);
        addr4.sin_addr.s_addr = htonl(ip.h);
        m_empty = false;
    }

    void SockAddr_deprecated::setIPv6(huint128_t ip)
    {
        return setIPv6(ToNet(ip));
    }

    void SockAddr_deprecated::setIPv6(nuint128_t ip)
    {
        std::memcpy(&addr6.sin6_addr, &ip, sizeof(addr6.sin6_addr));
        if (isIPv4())
        {
            setIPv4(
                addr6.sin6_addr.s6_addr[12],
                addr6.sin6_addr.s6_addr[13],
                addr6.sin6_addr.s6_addr[14],
                addr6.sin6_addr.s6_addr[15]);
            addr4.sin_port = addr6.sin6_port;
        }
    }

    void SockAddr_deprecated::setPort(nuint16_t port)
    {
        addr6.sin6_port = port.n;
        addr4.sin_port = port.n;
    }

    void SockAddr_deprecated::setPort(huint16_t port)
    {
        setPort(ToNet(port));
    }

    net::port_t SockAddr_deprecated::port() const
    {
        return net::port_t{addr6.sin6_port};
    }

}  // namespace llarp
