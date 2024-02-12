#pragma once

#include "identity.hpp"
#include "protocol.hpp"

#include <llarp/crypto/types.hpp>

namespace llarp::service
{
    struct AsyncKeyExchange : public std::enable_shared_from_this<AsyncKeyExchange>
    {
        SharedSecret sharedKey;
        ServiceInfo m_remote;
        const Identity& m_LocalIdentity;
        ProtocolMessage msg;
        Introduction intro;
        const PQPubKey introPubKey;
        Introduction remoteIntro;
        std::function<void(std::shared_ptr<ProtocolFrameMessage>)> hook;
        Endpoint* handler;
        SessionTag tag;

        AsyncKeyExchange(
            ServiceInfo r,
            const Identity& localident,
            const PQPubKey& introsetPubKey,
            const Introduction& remote,
            Endpoint* h,
            const SessionTag& t);

        static void Result(std::shared_ptr<AsyncKeyExchange> user, std::shared_ptr<ProtocolFrameMessage> frame);

        /// given protocol message make protocol frame
        static void Encrypt(std::shared_ptr<AsyncKeyExchange> user, std::shared_ptr<ProtocolFrameMessage> frame);
    };

}  // namespace llarp::service
