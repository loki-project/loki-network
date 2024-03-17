#pragma once

#include <llarp/net/net.hpp>
#include <llarp/util/aligned.hpp>

namespace llarp::service
{
    struct SessionTag final : AlignedBuffer<16>
    {
        using AlignedBuffer<16>::AlignedBuffer;

        void Randomize() override;

        sockaddr_in6 to_v6() const;

        void from_v6(sockaddr_in6 saddr);
    };
}  // namespace llarp::service

namespace std
{
    template <>
    struct hash<llarp::service::SessionTag>
    {
        size_t operator()(const llarp::service::SessionTag& tag) const
        {
            std::hash<std::string_view> h{};
            return h(std::string_view{reinterpret_cast<const char*>(tag.data()), tag.size()});
        }
    };
}  // namespace std
