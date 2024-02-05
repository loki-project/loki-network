#pragma once
#include <llarp/util/types.hpp>

#include <functional>
#include <vector>

namespace llarp::vpn
{
    using PacketSendFunc_t = std::function<void(std::vector<uint8_t>)>;
    using PacketInterceptFunc_t = std::function<void(std::vector<uint8_t>, PacketSendFunc_t)>;

    class I_PacketInterceptor
    {
       public:
        virtual ~I_PacketInterceptor() = default;

        /// start intercepting packets and call a callback for each one we get
        /// the callback passes in an ip packet and a function that we can use to send an ip packet
        /// to its origin
        virtual void start(PacketInterceptFunc_t f) = 0;

        /// stop intercepting packets
        virtual void stop() = 0;
    };

}  // namespace llarp::vpn
