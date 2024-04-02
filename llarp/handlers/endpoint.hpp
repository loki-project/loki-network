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
                                 public EndpointBase,
                                 public std::enable_shared_from_this<LocalEndpoint>
    {
      private:
        bool _is_exit_node{false};
        bool _is_snode_service{false};  // TODO:
        bool _is_v4;

        std::string _name;

        std::string _if_name;
        oxen::quic::Address _local_addr;
        IPRange _local_range;
        ip _local_ip;

        service::Identity _identity;
        service::IntroSet _local_introset;

        std::chrono::milliseconds _last_introset_regen_attempt{0s};

        // From config -- only in exit mode
        std::set<IPRange> _routed_ranges;

      public:
        LocalEndpoint(std::string name, Router& r);

        ~LocalEndpoint() override = default;

        bool configure(NetworkConfig& conf, DnsConfig& dnsConf);

        void regen_and_publish_introset();

        bool publish_introset(const service::EncryptedIntroSet& introset);

        void build_more(size_t n = 0) override;

        void lookup_intro(
            const dht::Key_t& location, bool is_relayed, uint64_t order, std::function<void(std::string)> func);

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

        std::string name() const override
        {
            return _name;
        }

        oxen::quic::Address local_address() const override
        {
            return _local_addr;
        }

        const std::shared_ptr<EventLoop>& loop() override;

        void srv_records_changed() override;
    };
}  //  namespace llarp::handlers
