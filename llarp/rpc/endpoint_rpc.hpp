#pragma once

#include <llarp/service/auth.hpp>
#include <llarp/service/convotag.hpp>

#include <oxenmq/oxenmq.h>

namespace llarp::service
{
    struct Endpoint;
}

namespace llarp::rpc
{
    struct EndpointAuthRPC : public llarp::service::IAuthPolicy, public std::enable_shared_from_this<EndpointAuthRPC>
    {
        using LMQ_ptr = std::shared_ptr<oxenmq::OxenMQ>;
        using Endpoint_ptr = std::shared_ptr<llarp::service::Endpoint>;
        using Whitelist_t = std::unordered_set<llarp::service::Address>;

        explicit EndpointAuthRPC(
            std::string url,
            std::string method,
            Whitelist_t addr_whitelist,
            std::unordered_set<std::string> token_whitelist,
            LMQ_ptr lmq,
            Endpoint_ptr endpoint);

        ~EndpointAuthRPC() override = default;

        void Start();

        void authenticate_async(
            std::shared_ptr<llarp::service::ProtocolMessage> msg, std::function<void(std::string, bool)> hook) override;

        bool auth_async_pending(service::ConvoTag tag) const override;

      private:
        const std::string m_AuthURL;
        const std::string m_AuthMethod;
        const Whitelist_t m_AuthWhitelist;
        const std::unordered_set<std::string> m_AuthStaticTokens;
        LMQ_ptr m_LMQ;
        Endpoint_ptr m_Endpoint;
        std::optional<oxenmq::ConnectionID> m_Conn;
        std::unordered_set<service::ConvoTag> m_PendingAuths;
    };
}  // namespace llarp::rpc
