#include "endpoint.hpp"

#include <llarp/router/router.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("local_endpoint");

    LocalEndpoint::LocalEndpoint(std::string name, Router& r)
        : path::PathHandler{r, 3, path::DEFAULT_LEN}, _is_exit_node{_router.is_exit_node()}, _name{std::move(name)}
    {}

    const std::shared_ptr<EventLoop>& LocalEndpoint::loop()
    {
        return _router.loop();
    }

    void LocalEndpoint::srv_records_changed()
    {
        // TODO: Investigate the usage or the term exit RE: service nodes acting as exits
        // ^^ lol
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

    bool LocalEndpoint::configure(NetworkConfig& netconf, DnsConfig& dnsconf)
    {
        _is_exit_node = _router.is_exit_node();
        // _is_snode_service = _router.is

        (void)dnsconf;

        if (_is_exit_node)
        {
            if (not netconf._routed_ranges.empty())
            {
                _routed_ranges.merge(netconf._routed_ranges);
                _local_introset._routed_ranges = _routed_ranges;
            }

            _local_introset.exit_policy = netconf.traffic_policy;
        }

        _if_name = *netconf._if_name;
        _local_range = *netconf._local_ip_range;
        _local_addr = *netconf._local_addr;
        _local_ip = *netconf._local_ip;

        return true;
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
    void LocalEndpoint::regen_and_publish_introset()
    {
        const auto now = llarp::time_now_ms();
        _last_introset_regen_attempt = now;
        std::set<service::Introduction, service::IntroExpiryComparator> intros;

        if (auto maybe_intros = get_path_intros_conditional([now](const service::Introduction& intro) -> bool {
                return not intro.expires_soon(now, path::INTRO_STALE_THRESHOLD);
            }))
        {
            intros.merge(*maybe_intros);
        }
        else
        {
            log::warning(logcat, "{} failed to get enough valid path introductions to publish introset!", name());
            return build_more(1);
        }

        _local_introset.supported_protocols.clear();
    }

    void LocalEndpoint::handle_initiation_session(ustring decrypted_payload)
    {
        (void)decrypted_payload;
    }

    bool LocalEndpoint::publish_introset(const service::EncryptedIntroSet& introset)
    {
        (void)introset;
        return true;
    }

}  //  namespace llarp::handlers
