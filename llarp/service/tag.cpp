#include "tag.hpp"

namespace llarp::service
{
    void SessionTag::Randomize()
    {
        llarp::AlignedBuffer<16>::Randomize();
        /// ensure we are in the fc00 range
        llarp::AlignedBuffer<16>::operator[](0) = 0xfc;
    }

    sockaddr_in6 SessionTag::to_v6() const
    {
        sockaddr_in6 saddr{};
        saddr.sin6_family = AF_INET6;
        std::copy_n(data(), size(), saddr.sin6_addr.s6_addr);
        return saddr;
    }

    void SessionTag::from_v6(sockaddr_in6 saddr)
    {
        std::copy_n(saddr.sin6_addr.s6_addr, size(), data());
    }

}  // namespace llarp::service
