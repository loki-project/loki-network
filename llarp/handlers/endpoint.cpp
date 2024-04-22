#include "endpoint.hpp"

#include <llarp/messages/session.hpp>
#include <llarp/router/router.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("LocalEndpoint");

    LocalEndpoint::LocalEndpoint(Router& r)
        : path::PathHandler{r, path::DEFAULT_PATHS_HELD, path::DEFAULT_LEN}, _is_exit_node{_router.is_exit_node()}
    {}

    const std::shared_ptr<EventLoop>& LocalEndpoint::loop()
    {
        return _router.loop();
    }

    void LocalEndpoint::srv_records_changed()
    {
        // TODO: Investigate the usage or the term exit RE: service nodes acting as exits
        // ^^ lol
        _local_introset.SRVs.clear();

        for (const auto& srv : srv_records())
        {
            _local_introset.SRVs.emplace_back(srv);
        }

        regen_and_publish_introset();
    }

    void LocalEndpoint::build_more(size_t n)
    {
        size_t count{0};
        log::debug(logcat, "LocalEndpoint building {} paths to random remotes (needed: {})", n, NUM_ONS_LOOKUP_PATHS);

        for (size_t i = 0; i < n; ++i)
        {
            count += build_path_to_random();
        }

        if (count == n)
            log::debug(logcat, "LocalEndpoint successfully initiated {} path-builds", n);
        else
            log::warning(logcat, "LocalEndpoint only initiated {} path-builds (needed: {})", count, n);
    }

    void LocalEndpoint::configure()
    {
        auto net_config = _router.config()->network;

        if (net_config.is_reachable)
            should_publish_introset = true;

        _is_exit_node = _router.is_exit_node();
        _is_snode_service = _router.is_service_node();

        if (_is_exit_node)
        {
            assert(not _is_snode_service);

            if (not net_config._routed_ranges.empty())
            {
                _routed_ranges.merge(net_config._routed_ranges);
                _local_introset._routed_ranges = _routed_ranges;
            }

            _exit_policy = net_config.traffic_policy;
            _local_introset.exit_policy = _exit_policy;
        }

        if (not net_config.srv_records.empty())
            _local_introset.SRVs = std::move(net_config.srv_records);

        if (use_tokens = not net_config.auth_static_tokens.empty(); use_tokens)
            _static_auth_tokens.merge(net_config.auth_static_tokens);

        if (use_whitelist = not net_config.auth_whitelist.empty(); use_whitelist)
            _auth_whitelist.merge(net_config.auth_whitelist);

        _if_name = *net_config._if_name;
        _local_range = *net_config._local_ip_range;
        _local_addr = *net_config._local_addr;
        _local_ip = *net_config._local_ip;

        _is_v4 = _local_range.is_ipv4();
    }

    void LocalEndpoint::lookup_intro(
        const dht::Key_t& location, bool is_relayed, uint64_t order, std::function<void(std::string)> func)
    {
        (void)location;
        (void)is_relayed;
        (void)order;
        (void)func;
    }

    /** Introset publishing:
        - When a local service or exit node publishes an introset, it is also sent along the path currently used
            for that session
        -
    */
    // TODO: this
    void LocalEndpoint::regen_and_publish_introset()
    {
        const auto now = llarp::time_now_ms();
        _last_introset_regen_attempt = now;

        std::set<service::Introduction, service::IntroExpiryComparator> path_intros;

        if (auto maybe_intros = get_path_intros_conditional([now](const service::Introduction& intro) -> bool {
                return not intro.expires_soon(now, path::INTRO_STALE_THRESHOLD);
            }))
        {
            path_intros.merge(*maybe_intros);
        }
        else
        {
            log::warning(logcat, "Failed to get enough valid path introductions to publish introset!");
            return build_more(1);
        }

        auto& intro_protos = _local_introset.supported_protocols;
        intro_protos.clear();

        if (_router.using_tun_if())
        {
            intro_protos.push_back(_is_v4 ? service::ProtocolType::TrafficV4 : service::ProtocolType::TrafficV6);

            if (_is_exit_node)
            {
                intro_protos.push_back(service::ProtocolType::Exit);
                _local_introset.exit_policy = _exit_policy;
                _local_introset._routed_ranges = _routed_ranges;
            }
        }

        intro_protos.push_back(service::ProtocolType::TCP2QUIC);

        auto& intros = _local_introset.intros;
        intros.clear();

        for (auto& intro : path_intros)
        {
            if (intros.size() < num_paths_desired)
                intros.emplace(std::move(intro));
        }

        // We already check that path_intros is not empty, so we can assert here
        assert(not intros.empty());

        if (auto maybe_encrypted = _identity.encrypt_and_sign_introset(_local_introset, now))
        {
            if (publish_introset(*maybe_encrypted))
            {
                log::debug(logcat, "Successfully republished encrypted introset");
            }
            else
                log::warning(logcat, "Failed to republish encrypted introset!");
        }
        else
            log::warning(logcat, "Failed to encrypt and sign introset!");
    }

    bool LocalEndpoint::validate(const NetworkAddress& remote, std::optional<std::string> maybe_auth)
    {
        bool ret{true};

        if (use_tokens)
            ret &= _static_auth_tokens.contains(*maybe_auth);

        if (use_whitelist)
            ret &= _auth_whitelist.contains(remote);

        return ret;
    }

    bool LocalEndpoint::prefigure_session(
        NetworkAddress initiator, service::SessionTag tag, std::shared_ptr<path::Path> path)
    {
        assert(path->is_client_path());

        auto inbound = std::make_shared<session::InboundSession>(initiator, std::move(path), *this, std::move(tag));

        auto [session, _] = _sessions.insert_or_assign(std::move(initiator), std::move(inbound));

        log::info(
            logcat, "LocalEndpoint successfully created and mapped InboundSession object! Starting TCP tunnel...");

        session->tcp_backend_connect();

        return true;
    }

    bool LocalEndpoint::publish_introset(const service::EncryptedIntroSet& introset)
    {
        bool ret{true};

        {
            Lock_t l{paths_mutex};

            for (const auto& [rid, path] : _paths)
            {
                log::debug(logcat, "Publishing introset to pivot {}", path->pivot_rid());

                ret += path->publish_intro(introset, true);
            }
        }

        return ret;
    }

}  //  namespace llarp::handlers
