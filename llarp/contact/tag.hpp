#pragma once

// #include <llarp/net/net.hpp>
#include <llarp/util/aligned.hpp>

namespace llarp
{
    struct SessionTag final : AlignedBuffer<16>
    {
        using AlignedBuffer<16>::AlignedBuffer;

        static SessionTag make_random();

        void Randomize() override;
    };
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::SessionTag>
    {
        size_t operator()(const llarp::SessionTag& tag) const
        {
            std::hash<std::string_view> h{};
            return h(std::string_view{reinterpret_cast<const char*>(tag.data()), tag.size()});
        }
    };
}  // namespace std
