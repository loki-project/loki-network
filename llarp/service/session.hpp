#pragma once

#include "info.hpp"
#include "intro.hpp"

#include <llarp/crypto/types.hpp>
#include <llarp/path/path.hpp>
#include <llarp/util/types.hpp>

namespace llarp::service
{
    static constexpr auto SessionLifetime = path::DEFAULT_LIFETIME * 2;

    struct Session
    {
        /// the intro we have
        Introduction replyIntro;
        SharedSecret sharedKey;
        ServiceInfo remote;
        /// the intro they have
        Introduction intro;

        /// the sequence number we are to use for the next message
        uint64_t seqno = 0;

        /// number of remote messages we sent to them
        uint64_t messagesSend = 0;
        /// number of remote messages we got from them
        uint64_t messagesRecv = 0;

        bool inbound = false;
        bool forever = false;

        Duration_t lastSend{};
        Duration_t lastRecv{};

        StatusObject ExtractStatus() const;

        /// called to indicate we recieved on this session
        void RX();

        /// called to indicate we transimitted on this session
        void TX();

        bool IsExpired(llarp_time_t now, llarp_time_t lifetime = SessionLifetime) const;

        Address Addr() const;
    };

}  // namespace llarp::service
