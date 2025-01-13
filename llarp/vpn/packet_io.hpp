#pragma once

#include <llarp/net/ip_packet.hpp>

#include <functional>

namespace llarp::vpn
{
    class PacketIO
    {
      public:
        virtual ~PacketIO() = default;

        /// start any platform specific operations before running
        virtual void Start(){};

        /// stop operation and tear down anything that Start() set up.
        virtual void Stop(){};

        /// read next ip packet, return an empty packet if there are none ready.
        virtual IPPacket read_next_packet() = 0;

        /// write a packet to the interface
        /// returns false if we dropped it
        virtual bool write_packet(IPPacket pkt) = 0;

        /// get pollable fd for reading
        virtual int PollFD() const = 0;
    };

}  // namespace llarp::vpn
