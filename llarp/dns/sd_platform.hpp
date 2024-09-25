#pragma once
#include "platform.hpp"

#include <llarp/constants/platform.hpp>

#include <type_traits>

namespace llarp::dns
{
    namespace sd
    {
        /// a dns platform that sets dns via systemd resolved
        class Platform : public I_Platform
        {
          public:
            ~Platform() override = default;

            void set_resolver(unsigned int if_index, oxen::quic::Address dns, bool global) override;
        };
    }  // namespace sd
    using SD_Platform_t = std::conditional_t<llarp::platform::has_systemd, sd::Platform, Null_Platform>;
}  // namespace llarp::dns
