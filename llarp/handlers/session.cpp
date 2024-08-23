#include "session.hpp"

#include <llarp/link/contacts.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/messages/session.hpp>
#include <llarp/router/router.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("SessionHandler");

    SessionEndpoint::SessionEndpoint(Router& r)
        : path::PathHandler{r, path::DEFAULT_PATHS_HELD, path::DEFAULT_LEN},
          _is_exit_node{_router.is_exit_node()},
          _is_snode_service{_router.is_service_node()}
    {}

    const std::shared_ptr<EventLoop>& SessionEndpoint::loop()
    {
        return _router.loop();
    }

    void SessionEndpoint::tick(std::chrono::milliseconds now)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        log::critical(logcat, "SessionEndpoint ticking outbound sessions...");
        _sessions.tick_outbounds(now);

        path::PathHandler::tick(now);
    }

    void SessionEndpoint::configure()
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
        _local_base_ip = *net_config._local_base_ip;

        _is_v4 = _local_range.is_ipv4();

        // TESTNET: TODO: check if ipv6 is disabled
        for (auto& [addr, range] : net_config._exit_ranges)
        {
            _range_map.insert_or_assign(range, addr);
        }

        if (not net_config.exit_auths.empty())
        {
            _auth_tokens.merge(net_config.exit_auths);
        }
    }

    void SessionEndpoint::build_more(size_t n)
    {
        size_t count{0};
        log::debug(
            logcat, "SessionEndpoint building {} paths to random remotes (needed: {})", n, path::DEFAULT_PATHS_HELD);

        for (size_t i = 0; i < n; ++i)
        {
            count += build_path_to_random();
        }

        if (count == n)
            log::debug(logcat, "SessionEndpoint successfully initiated {} path-builds", n);
        else
            log::warning(logcat, "SessionEndpoint only initiated {} path-builds (needed: {})", count, n);
    }

    void SessionEndpoint::srv_records_changed()
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

    void SessionEndpoint::resolve_ons_mappings()
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);
        auto& ons_ranges = _router.config()->network._ons_ranges;

        if (auto n_ons_ranges = ons_ranges.size(); n_ons_ranges > 0)
        {
            log::info(logcat, "SessionEndpoint resolving {} ONS addresses mapped to IP ranges", n_ons_ranges);

            for (auto itr = ons_ranges.begin(); itr != ons_ranges.end();)
            {
                resolve_ons(
                    std::move(itr->first),
                    [this, ip_range = std::move(itr->second)](std::optional<NetworkAddress> maybe_addr) {
                        if (maybe_addr)
                        {
                            log::debug(
                                logcat,
                                "Successfully resolved ONS lookup for {} mapped to IPRange:{}",
                                *maybe_addr,
                                ip_range);
                            _range_map.insert_or_assign(std::move(ip_range), std::move(*maybe_addr));
                        }
                        // we don't need to print a fail message, as it is logged prior to invoking with std::nullopt
                    });

                itr = ons_ranges.erase(itr);
            }
        }

        auto& ons_auths = _router.config()->network.ons_exit_auths;

        if (auto n_ons_auths = ons_auths.size(); n_ons_auths > 0)
        {
            log::debug(logcat, "SessionEndpoint resolving {} ONS addresses mapped to auth tokens", n_ons_auths);

            for (auto itr = ons_auths.begin(); itr != ons_auths.end();)
            {
                resolve_ons(
                    std::move(itr->first),
                    [this, auth_token = std::move(itr->second)](std::optional<NetworkAddress> maybe_addr) {
                        if (maybe_addr)
                        {
                            log::debug(
                                logcat,
                                "Successfully resolved ONS lookup for {} mapped to static auth token",
                                *maybe_addr);
                            _auth_tokens.emplace(std::move(*maybe_addr), std::move(auth_token));
                        }
                        // we don't need to print a fail message, as it is logged prior to invoking with std::nullopt
                    });

                itr = ons_auths.erase(itr);
            }
        }
    }

    void SessionEndpoint::resolve_ons(std::string ons, std::function<void(std::optional<NetworkAddress>)> func)
    {
        if (not service::is_valid_ons(ons))
        {
            log::debug(logcat, "Invalid ONS name ({}) queried for lookup", ons);
            return func(std::nullopt);
        }

        log::debug(logcat, "Looking up ONS name {}", ons);

        auto response_handler = [ons_name = ons, hook = std::move(func)](std::string response) {
            if (auto record = service::EncryptedONSRecord::construct(response);
                auto client_addr = record->decrypt(ons_name))
            {
                return hook(std::move(client_addr));
            }

            std::optional<std::string> status = std::nullopt;

            try
            {
                oxenc::bt_dict_consumer btdc{response};

                if (auto s = btdc.maybe<std::string>(messages::STATUS_KEY))
                    status = s;
            }
            catch (...)
            {
                log::warning(logcat, "Exception caught parsing 'find_name' response!");
            }

            log::warning(logcat, "Call to endpoint 'lookup_name' failed -- status:{}", status.value_or("<none given>"));
            hook(std::nullopt);
        };

        {
            Lock_t l{paths_mutex};

            for (const auto& [rid, path] : _paths)
            {
                log::info(logcat, "Querying pivot:{} for name lookup (target: {})", path->pivot_rid(), ons);

                path->resolve_ons(ons, response_handler);
            }
        }
    }

    void SessionEndpoint::lookup_intro(
        RouterID remote, bool is_relayed, uint64_t order, std::function<void(std::optional<service::IntroSet>)> func)
    {
        if (auto maybe_intro = _router.contacts().get_decrypted_introset(remote))
        {
            log::debug(logcat, "Decrypted introset for remote (rid:{}) found locally~", remote);
            return func(std::move(maybe_intro));
        }

        log::debug(logcat, "Looking up introset for remote (rid:{})", remote);
        auto remote_key = dht::Key_t::derive_from_rid(remote);

        auto response_handler = [this, remote, hook = std::move(func)](std::string response) {
            if (auto encrypted = service::EncryptedIntroSet::construct(response);
                auto intro = encrypted->decrypt(remote))
            {
                log::debug(logcat, "Storing introset for remote (rid:{})", remote);
                _router.contacts().put_intro(std::move(*encrypted));
                return hook(std::move(intro));
            }

            std::optional<std::string> status = std::nullopt;

            try
            {
                oxenc::bt_dict_consumer btdc{response};

                if (auto s = btdc.maybe<std::string>(messages::STATUS_KEY))
                    status = s;
            }
            catch (...)
            {
                log::warning(logcat, "Exception caught parsing 'find_intro' response!");
            }

            log::warning(logcat, "Call to endpoint 'find_intro' failed -- status:{}", status.value_or("<none given>"));
            hook(std::nullopt);
        };

        {
            Lock_t l{paths_mutex};

            for (const auto& [rid, path] : _paths)
            {
                log::info(
                    logcat, "Querying pivot (rid:{}) for introset lookup target (rid:{})", path->pivot_rid(), remote);

                path->find_intro(remote_key, is_relayed, order, response_handler);
            }
        }
    }

    /** Introset publishing:
        - When a local service or exit node publishes an introset, it is also sent along the path currently used
            for that session
    */
    // TODO: this
    void SessionEndpoint::regen_and_publish_introset()
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

    bool SessionEndpoint::validate(const NetworkAddress& remote, std::optional<std::string> maybe_auth)
    {
        bool ret{true};

        if (use_tokens)
            ret &= _static_auth_tokens.contains(*maybe_auth);

        if (use_whitelist)
            ret &= _auth_whitelist.contains(remote);

        return ret;
    }

    bool SessionEndpoint::prefigure_session(
        NetworkAddress initiator, service::SessionTag tag, std::shared_ptr<path::Path> path, bool use_tun)
    {
        bool ret = true;
        assert(path->is_client_path());

        auto inbound =
            std::make_shared<session::InboundSession>(initiator, std::move(path), *this, std::move(tag), use_tun);

        auto [session, _] = _sessions.insert_or_assign(std::move(initiator), std::move(inbound));

        auto msg = "SessionEndpoint successfully created and mapped InboundSession object!";

        // TESTNET:
        // instruct the lokinet TUN device to create a mapping from a local IP to this session
        if (session->using_tun())
        {
            log::info(logcat, "{} Instructing lokinet TUN device to create mapped route...", msg);

            if (auto maybe_ip = _router.tun_endpoint()->map_session_to_local_ip(session->remote()))
            {
                log::info(
                    logcat,
                    "TUN device successfully routing session (remote: {}) via local ip: {}",
                    session->remote(),
                    std::holds_alternative<ipv4>(*maybe_ip) ? std::get<ipv4>(*maybe_ip).to_string()
                                                            : std::get<ipv6>(*maybe_ip).to_string());
            }
            else
            {
                // TODO: if this fails, we should close the session
            }
        }
        else
        {
            log::info(logcat, "{} Connecting to TCP backend to route session traffic...", msg);
            // session->tcp_backend_connect();
        }

        return ret;
    }

    bool SessionEndpoint::publish_introset(const service::EncryptedIntroSet& introset)
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

    std::optional<std::string_view> SessionEndpoint::fetch_auth_token(const NetworkAddress& remote) const
    {
        std::optional<std::string_view> ret = std::nullopt;

        if (auto itr = _auth_tokens.find(remote); itr != _auth_tokens.end())
            ret = itr->second;

        return ret;
    }

    void SessionEndpoint::_make_session(
        NetworkAddress remote, std::shared_ptr<path::Path> path, on_session_init_hook cb, bool is_exit)
    {
        auto tag = service::SessionTag::make_random();

        path->send_path_control_message(
            "session_init",
            InitiateSession::serialize_encrypt(
                _router.local_rid(),
                remote.router_id(),
                tag,
                path->pivot_txid(),
                fetch_auth_token(remote),
                _router.using_tun_if()),
            [this, remote, tag, path, hook = std::move(cb), is_exit](std::string response) {
                if (response == messages::OK_RESPONSE)
                {
                    auto outbound = std::make_shared<session::OutboundSession>(
                        remote, *this, std::move(path), std::move(tag), is_exit);

                    auto [session, _] = _sessions.insert_or_assign(std::move(remote), std::move(outbound));

                    auto msg = "SessionEndpoint successfully created and mapped InboundSession object!";

                    // TESTNET:
                    if (session->using_tun())
                    {
                        log::info(logcat, "{} Instructing lokinet TUN device to create mapped route...", msg);
                        if (auto maybe_ip = _router.tun_endpoint()->map_session_to_local_ip(session->remote()))
                        {
                            log::info(
                                logcat, "TUN device successfully routing session to remote: {}", session->remote());

                            hook(*maybe_ip);
                        }
                        else
                        {
                            // TODO: if this fails, we should close the session
                        }
                    }
                    else
                    {
                        log::info(logcat, "{} Starting TCP listener to route session traffic to backend...", msg);
                        session->tcp_backend_listen(std::move(hook));
                    }
                }
            });
    }

    void SessionEndpoint::_make_session_path(
        service::IntroductionSet intros, NetworkAddress remote, on_session_init_hook cb, bool is_exit)
    {
        // we can recurse through this function as we remove the first pivot of the set of introductions every
        // invocation
        if (intros.empty())
        {
            log::critical(
                logcat, "Exhausted all pivots associated with remote (rid:{}); failed to make session!", remote);
            return;
        }

        auto intro = intros.extract(intros.begin()).value();
        auto pivot = intro.pivot_router;

        // DISCUSS: we don't share paths, but if every successful path-build is logged in PathContext, we are
        // effectively sharing across all path-building objects...?
        if (auto path_ptr = _router.path_context()->get_path(intro.pivot_hop_id))
        {
            log::info(logcat, "Found path to pivot (hopid: {}); initiating session!", intro.pivot_hop_id);
            return _make_session(std::move(remote), std::move(path_ptr), std::move(cb), is_exit);
        }

        log::info(logcat, "Initiating session path-build to remote:{} via pivot:{}", remote, pivot);

        auto maybe_hops = aligned_hops_to_remote(pivot);

        if (not maybe_hops)
        {
            log::error(logcat, "Failed to get hops for path-build to pivot:{}", pivot);
            return;
        }

        auto& hops = *maybe_hops;
        assert(pivot == hops.back().router_id());

        auto path = std::make_shared<path::Path>(_router, std::move(hops), get_weak(), true, remote.is_client());

        log::info(logcat, "Building path -> {} : {}", path->to_string(), path->HopsString());

        auto payload = build2(path);

        if (not build3(
                path->upstream_rid(),
                std::move(payload),
                [this, path, intros, remote, hook = std::move(cb), is_exit](oxen::quic::message m) {
                    if (m)
                    {
                        // Do not call ::add_path() or ::path_build_succeeded() here; OutboundSession constructor will
                        // take care of both path storage and logging in PathContext
                        log::info(logcat, "Path build to remote:{} succeeded, initiating session!", remote);
                        return _make_session(std::move(remote), std::move(path), std::move(hook), is_exit);
                    }

                    try
                    {
                        if (m.timed_out)
                        {
                            log::warning(logcat, "Path build request for session initiation timed out!");
                        }
                        else
                        {
                            oxenc::bt_dict_consumer d{m.body()};
                            auto status = d.require<std::string_view>(messages::STATUS_KEY);
                            log::warning(logcat, "Path build returned failure status: {}", status);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        log::warning(
                            logcat,
                            "Exception caught parsing path build response for session initiation: {}",
                            e.what());
                    }

                    // recurse with introduction set minus the recently attempted pivot
                    _make_session_path(std::move(intros), std::move(remote), std::move(hook), is_exit);
                }))
        {
            log::critical(logcat, "Error sending path_build control message for session initiation!");
        }
    }

    bool SessionEndpoint::_initiate_session(NetworkAddress remote, on_session_init_hook cb, bool is_exit)
    {
        if (is_exit and not remote.is_client())
            throw std::runtime_error{"Cannot initiate exit session to remote service node!"};

        auto counter = std::make_shared<size_t>(path::DEFAULT_PATHS_HELD);

        _router.loop()->call([this, remote, handler = std::move(cb), is_exit, counter]() {
            lookup_intro(
                remote.router_id(),
                false,
                0,
                [this, remote, hook = std::move(handler), is_exit, counter](std::optional<service::IntroSet> intro) {
                    // already have a successful return
                    if (*counter == 0)
                        return;

                    if (intro)
                    {
                        *counter = 0;
                        log::info(logcat, "Session initiation returned successful 'lookup_intro'...");
                        _make_session_path(std::move(intro->intros), remote, std::move(hook), is_exit);
                    }
                    else if (--*counter == 0)
                    {
                        log::warning(logcat, "Failed to initiate session at 'lookup_intro' (target:{})", remote);
                    }
                });
        });

        return true;
    }

    void SessionEndpoint::map_remote_to_local_addr(NetworkAddress remote, oxen::quic::Address local)
    {
        _address_map.insert_or_assign(std::move(local), std::move(remote));
    }

    void SessionEndpoint::unmap_local_addr_by_remote(const NetworkAddress& remote)
    {
        _address_map.unmap(remote);
    }

    void SessionEndpoint::unmap_remote_by_name(const std::string& name)
    {
        _address_map.unmap(name);
    }

    void SessionEndpoint::map_remote_to_local_range(NetworkAddress remote, IPRange range)
    {
        _range_map.insert_or_assign(std::move(range), std::move(remote));
    }

    void SessionEndpoint::unmap_local_range_by_remote(const NetworkAddress& remote)
    {
        _range_map.unmap(remote);
    }

    void SessionEndpoint::unmap_range_by_name(const std::string& name)
    {
        _range_map.unmap(name);
    }

}  //  namespace llarp::handlers
