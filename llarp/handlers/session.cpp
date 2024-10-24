#include "session.hpp"

#include <llarp/contact/contactdb.hpp>
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

        log::trace(logcat, "SessionEndpoint ticking outbound sessions...");
        _sessions.tick_outbounds(now);

        path::PathHandler::tick(now);
    }

    bool SessionEndpoint::stop(bool send_close)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _running = false;

        Lock_t l{paths_mutex};

        _sessions.stop_sessions(send_close);

        return path::PathHandler::stop(send_close);
    }

    void SessionEndpoint::configure()
    {
        auto net_config = _router.config()->network;

        _is_exit_node = _router.is_exit_node();
        _is_snode_service = _router.is_service_node();

        if (_is_exit_node)
        {
            assert(not _is_snode_service);

            _exit_policy = net_config.traffic_policy;
            client_contact.exit_policy = _exit_policy;
        }

        if (not net_config.srv_records.empty())
        {
            _srv_records.merge(net_config.srv_records);
            client_contact.SRVs = _srv_records;
        }

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

        uint16_t protoflags = protocol_flag::TCP2QUIC;

        if (_router.using_tun_if())
            protoflags |= _is_v4 ? protocol_flag::IPV4 : protocol_flag::IPV6;

        if (_is_exit_node)
            protoflags |= protocol_flag::EXIT;

        auto& key_manager = _router.key_manager();

        client_contact = ClientContact::generate(
            key_manager->derive_subkey(),
            key_manager->identity_data.to_pubkey(),
            _srv_records,
            protoflags,
            _exit_policy);

        should_publish_cc = net_config.is_reachable;
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
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);
        update_and_publish_localcc(get_current_client_intros(), _srv_records);
    }

    void SessionEndpoint::start_tickers()
    {
        if (should_publish_cc)
        {
            log::critical(logcat, "Starting ClientContact publish ticker...");
            _cc_publisher = _router.loop()->call_every(
                CC_PUBLISH_INTERVAL,
                [this]() {
                    log::critical(logcat, "Updating and publishing ClientContact...");
                    update_and_publish_localcc(get_current_client_intros());
                },
                true);
        }
        else
            log::debug(logcat, "SessionEndpoint configured to NOT publish ClientContact...");
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
        if (not is_valid_ons(ons))
        {
            log::debug(logcat, "Invalid ONS name ({}) queried for lookup", ons);
            return func(std::nullopt);
        }

        log::debug(logcat, "Looking up ONS name {}", ons);

        auto response_handler = [ons_name = ons, hook = std::move(func)](std::string response) {
            if (auto record = EncryptedSNSRecord::construct(response); auto client_addr = record->decrypt(ons_name))
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

    void SessionEndpoint::lookup_client_intro(
        RouterID remote, bool is_relayed, uint64_t order, std::function<void(std::optional<ClientContact>)> func)
    {
        auto remote_key = dht::Key_t::derive_from_rid(remote);

        if (auto maybe_intro = _router.contact_db().get_decrypted_cc(remote))
        {
            log::info(logcat, "Decrypted clientcontact for remote (rid: {}) found locally!", remote);
            return func(std::move(maybe_intro));
        }

        log::debug(logcat, "Looking up clientcontact for remote (rid:{})", remote);

        auto response_handler = [this, remote, hook = std::move(func)](std::string response) mutable {
            try
            {
                auto enc = EncryptedClientContact::deserialize(response);

                if (auto intro = enc.decrypt(remote))
                {
                    log::info(logcat, "Storing ClientContact for remote rid:{}", remote);
                    _router.contact_db().put_cc(std::move(enc));
                    return hook(std::move(intro));
                }

                oxenc::bt_dict_consumer btdc{response};
                auto s = btdc.maybe<std::string_view>(messages::STATUS_KEY);

                log::warning(logcat, "Call to `find_cc` failed -- status: {}", s.value_or("< NONE GIVEN >"));
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception caught parsing FindClientContact response: {}", e.what());
            }

            hook(std::nullopt);
        };

        {
            Lock_t l{paths_mutex};

            for (const auto& [rid, path] : _paths)
            {
                log::debug(
                    logcat,
                    "Querying pivot (rid:{}) for clientcontact lookup target (rid:{})",
                    path->pivot_rid(),
                    remote);
                path->find_client_contact(remote_key, is_relayed, order, response_handler);
            }
        }
    }

    void SessionEndpoint::_localcc_update_fail()
    {
        log::warning(
            logcat,
            "Failed to query enough client introductions from current paths! Building more paths to publish "
            "introset");
        return build_more(1);
    }

    void SessionEndpoint::update_and_publish_localcc(intro_set intros)
    {
        if (intros.empty())
            return _localcc_update_fail();
        client_contact.regenerate(std::move(intros));
        _update_and_publish_localcc();
    }

    void SessionEndpoint::_update_and_publish_localcc()
    {
        try
        {
            auto enc = client_contact.encrypt_and_sign();

            if (publish_client_contact(enc))
                log::debug(logcat, "Successfully republished updated EncryptedClientContact!");
            else
                log::warning(logcat, "Failed to republish updated EncryptedClientContact!");
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "ClientContact encryption/signing exception: {}", e.what());
        }
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
                log::warning(logcat, "TUN devcice failed to route session (remote: {}) to local ip", session->remote());
                ret = false;
            }
        }
        else
        {
            log::info(logcat, "{} Connecting to TCP backend to route session traffic...", msg);
            // session->tcp_backend_connect();
        }

        return ret;
    }

    bool SessionEndpoint::publish_client_contact(const EncryptedClientContact& ecc)
    {
        bool ret{true};

        log::critical(logcat, "Publishing new EncryptedClientContact: {}", ecc.bt_payload());

        {
            Lock_t l{paths_mutex};

            for (const auto& [rid, path] : _paths)
            {
                log::debug(logcat, "Publishing ClientContact to pivot {}", path->pivot_rid());

                ret += path->publish_client_contact(ecc, true);
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
            [this, remote, tag, path, hook = std::move(cb), is_exit](std::string response) mutable {
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
        intro_set intros, NetworkAddress remote, on_session_init_hook cb, bool is_exit)
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
        auto& pivot = intro.pivot_rid;

        if (auto path = _router.path_context()->get_path(intro.pivot_hid))
        {
            log::info(logcat, "Found path to pivot (hopid: {}); initiating session!", intro.pivot_hid);
            return _make_session(std::move(remote), std::move(path), std::move(cb), is_exit);
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
                [this, path, intros, remote, hook = std::move(cb), is_exit](oxen::quic::message m) mutable {
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

        auto counter = std::make_shared<size_t>(num_paths_desired);

        _router.loop()->call([this, remote, handler = std::move(cb), is_exit, counter]() mutable {
            lookup_client_intro(
                remote.router_id(),
                false,
                0,
                [this, remote, hook = std::move(handler), is_exit, counter](std::optional<ClientContact> cc) {
                    if (*counter == 0)
                        return;

                    if (cc)
                    {
                        *counter = 0;
                        log::info(logcat, "Session initiation returned successful 'lookup_client_intro'...");
                        _make_session_path(std::move(cc->intros), remote, std::move(hook), is_exit);
                    }
                    else if (--*counter == 0)
                        log::warning(logcat, "Failed to initiate session at 'lookup_client_intro' (target:{})", remote);
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
