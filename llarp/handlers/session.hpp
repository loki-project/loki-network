#pragma once

#include <llarp/address/map.hpp>
#include <llarp/config/config.hpp>
#include <llarp/path/path_handler.hpp>
#include <llarp/service/identity.hpp>
#include <llarp/session/map.hpp>

namespace llarp
{
    inline constexpr size_t NUM_SESSION_PATHS{4};

    class EventLoop;

    namespace handlers
    {
        class SessionEndpoint final : public path::PathHandler, public std::enable_shared_from_this<SessionEndpoint>
        {
            bool _is_exit_node{false};
            bool _is_snode_service{false};

            std::unordered_set<dns::SRVData> _srv_records;

            bool should_publish_introset{true};

            session_map<NetworkAddress, session::BaseSession> _sessions;

            address_map<oxen::quic::Address, NetworkAddress> _address_map;

            // Remote client exit-node addresses mapped to local IP ranges
            //  - Directly pre-loaded from config
            address_map<IPRange, NetworkAddress> _range_map;

            service::Identity _identity;
            service::IntroSet _local_introset;

            std::chrono::milliseconds _last_introset_regen_attempt{0s};

            // auth tokens for making outbound sessions
            std::unordered_map<NetworkAddress, std::string> _auth_tokens;

            // static auth tokens for authenticating inbound sessions
            std::unordered_set<std::string> _static_auth_tokens;
            // whitelist for authenticating inbound sessions
            std::unordered_set<NetworkAddress> _auth_whitelist;

            bool use_tokens{false};
            bool use_whitelist{false};

            IPRange _local_range;
            oxen::quic::Address _local_addr;
            ip_v _local_base_ip;
            ip_v _next_ip;
            std::string _if_name;

            bool _is_v4;

            std::optional<std::string_view> fetch_auth_token(const NetworkAddress& remote) const;

            // Ranges reachable via our endpoint -- Exit mode only!
            std::set<IPRange> _routed_ranges;  // formerly from LocalEndpoint

            // policies about traffic that we are willing to carry -- Exit mode only!
            std::optional<net::TrafficPolicy> _exit_policy = std::nullopt;

          public:
            SessionEndpoint(Router& r);

            void configure();

            void build_more(size_t n = 0) override;

            const std::shared_ptr<EventLoop>& loop();

            std::shared_ptr<path::PathHandler> get_self() override { return shared_from_this(); }

            std::weak_ptr<path::PathHandler> get_weak() override { return weak_from_this(); }

            bool is_exit_node() const { return _is_exit_node; }

            bool is_snode_service() const { return _is_snode_service; }

            oxen::quic::Address local_address() const { return _local_addr; }

            const service::IntroSet& intro_set() const { return _local_introset; }

            // get copy of all srv records
            std::set<dns::SRVData> srv_records() const { return {_srv_records.begin(), _srv_records.end()}; }

            template <session::SessionType session_t = session::BaseSession>
            std::shared_ptr<session_t> get_session(const service::SessionTag& tag) const
            {
                return std::static_pointer_cast<session_t>(_sessions.get_session(tag));
            }

            template <session::SessionType session_t = session::BaseSession>
            std::shared_ptr<session_t> get_session(const NetworkAddress& remote) const
            {
                return std::static_pointer_cast<session_t>(_sessions.get_session(remote));
            }

            void srv_records_changed();

            void regen_and_publish_introset();

            bool publish_introset(const service::EncryptedIntroSet& introset);

            // SessionEndpoint can use either a whitelist or a static auth token list to  validate incomininbg requests
            // to initiate a session
            bool validate(const NetworkAddress& remote, std::optional<std::string> maybe_auth = std::nullopt);

            bool prefigure_session(
                NetworkAddress initiator, service::SessionTag tag, std::shared_ptr<path::Path> path, bool use_tun);

            // lookup ONS address to return "{pubkey}.loki" hidden service or exit node operated on a remote client
            void resolve_ons(std::string name, std::function<void(std::optional<NetworkAddress>)> func = nullptr);

            void lookup_remote_srv(
                std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler);

            void lookup_intro(
                RouterID remote,
                bool is_relayed,
                uint64_t order,
                std::function<void(std::optional<service::IntroSet>)> func);

            // resolves any config mappings that parsed ONS addresses to their pubkey network address
            void resolve_ons_mappings();

            bool initiate_remote_service_session(const NetworkAddress& remote, on_session_init_hook cb)
            {
                return _initiate_session(remote, std::move(cb), false);
            }

            bool initiate_remote_exit_session(const NetworkAddress& remote, on_session_init_hook cb)
            {
                return _initiate_session(remote, std::move(cb), true);
            }

            void Tick(std::chrono::milliseconds now) override;

            // TESTNET: the following functions may not be needed -- revisit this
            /*  Address Mapping - Public Mutators  */
            void map_remote_to_local_addr(NetworkAddress remote, oxen::quic::Address local);

            void unmap_local_addr_by_remote(const NetworkAddress& remote);

            void unmap_remote_by_name(const std::string& name);

            /*  IPRange Mapping - Public Mutators  */
            void map_remote_to_local_range(NetworkAddress remote, IPRange range);

            void unmap_local_range_by_remote(const NetworkAddress& remote);

            void unmap_range_by_name(const std::string& name);

          private:
            bool _initiate_session(NetworkAddress remote, on_session_init_hook cb, bool is_exit = false);

            void _make_session_path(
                service::IntroductionSet intros, NetworkAddress remote, on_session_init_hook cb, bool is_exit);

            void _make_session(
                NetworkAddress remote, std::shared_ptr<path::Path> path, on_session_init_hook cb, bool is_exit);
        };

    }  // namespace handlers
}  //  namespace llarp
