#pragma once

#include <llarp/address/map.hpp>
#include <llarp/config/config.hpp>
#include <llarp/endpoint_base.hpp>
#include <llarp/service/identity.hpp>

namespace llarp::handlers
{
    /** This class is the counterpart to handlers::RemoteHandler. While ::RemoteHandler manages sessions to remote
        hidden services and exits, ::LocalEndpoint manages the locally operated hidden service or exit node
    */
    struct LocalEndpoint final : public path::PathHandler,
                                 public EndpointBase<session::InboundSession>,
                                 public std::enable_shared_from_this<LocalEndpoint>
    {
      private:
        bool _is_exit_node{false};
        bool _is_snode_service{false};
        bool _is_v4;

        const std::string _name{"LocalEndpoint"};

        std::string _if_name;
        oxen::quic::Address _local_addr;
        IPRange _local_range;
        ip _local_ip;

        service::Identity _identity;
        service::IntroSet _local_introset;

        std::chrono::milliseconds _last_introset_regen_attempt{0s};

        std::unordered_set<std::string> _static_auth_tokens;
        std::unordered_set<NetworkAddress> _auth_whitelist;

        bool use_tokens{false};
        bool use_whitelist{false};

        // Ranges reachable via our endpoint -- Exit mode only!
        std::set<IPRange> _routed_ranges;

        // policies about traffic that we are willing to carry -- Exit mode only!
        std::optional<net::TrafficPolicy> _exit_policy = std::nullopt;

      public:
        LocalEndpoint(Router& r);

        ~LocalEndpoint() override = default;

        bool is_exit_node() const
        {
            return _is_exit_node;
        }

        bool is_snode_service() const
        {
            return _is_snode_service;
        }

        void configure();

        void regen_and_publish_introset();

        bool publish_introset(const service::EncryptedIntroSet& introset);

        void build_more(size_t n = 0) override;

        void lookup_intro(
            const dht::Key_t& location, bool is_relayed, uint64_t order, std::function<void(std::string)> func);

        // LocalEndpoint can use either a whitelist or a static auth token list to  validate incomininbg requests to
        // initiate a session
        bool validate(const NetworkAddress& remote, std::optional<std::string> maybe_auth = std::nullopt);

        bool prefigure_session(NetworkAddress initiator, service::SessionTag tag, std::shared_ptr<path::Path> path);

        const service::IntroSet& intro_set() const
        {
            return _local_introset;
        }

        std::shared_ptr<path::PathHandler> get_self() override
        {
            return shared_from_this();
        }

        std::weak_ptr<path::PathHandler> get_weak() override
        {
            return weak_from_this();
        }

        oxen::quic::Address local_address() const override
        {
            return _local_addr;
        }

        const std::shared_ptr<EventLoop>& loop() override;

        void srv_records_changed() override;
    };
}  //  namespace llarp::handlers
