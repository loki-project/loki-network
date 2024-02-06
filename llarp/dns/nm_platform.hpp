#pragma once
#include "platform.hpp"

#include <llarp/constants/platform.hpp>

#include <type_traits>
#include <unordered_map>

namespace llarp::dns
{
    namespace nm
    {
        // a dns platform that sets dns via network manager
        class Platform : public I_Platform
        {
           public:
            virtual ~Platform() = default;

            void set_resolver(unsigned int index, llarp::SockAddr_deprecated dns, bool global) override;
        };
    };  // namespace nm
    using NM_Platform_t = std::conditional_t<false, nm::Platform, Null_Platform>;
}  // namespace llarp::dns
