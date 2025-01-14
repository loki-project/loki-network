#include "session.hpp"

#include <llarp/contact/contactdb.hpp>
#include <llarp/messages/dht.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/messages/session.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/router/router.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("SessionHandler");

    SessionEndpoint::SessionEndpoint(Router& r)
        : path::PathHandler{r, path::DEFAULT_PATHS_HELD, path::DEFAULT_LEN},
          _is_exit_node{_router.is_exit_node()},
          _is_snode_service{_router.is_service_node()}
    {}

    const std::shared_ptr<EventLoop>& SessionEndpoint::loop() { return _router.loop(); }

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

        if (_cc_publisher)
        {
            log::debug(logcat, "ClientContact publish ticker stopped!");
            _cc_publisher->stop();
        }

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

        uint16_t protoflags = meta::to_underlying(protocol_flag::TCP2QUIC);

        if (_router.using_tun_if())
            protoflags |= meta::to_underlying(_is_v4 ? protocol_flag::IPV4 : protocol_flag::IPV6);

        if (_is_exit_node)
            protoflags |= meta::to_underlying(protocol_flag::EXIT);

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
        log::debug(logcat, "SessionEndpoint building {} paths to random remotes (needed: {})", n, num_paths_desired);

        // TESTNET: ensure one path is built to pivot
        RouterID pivot{oxenc::from_base32z("55fxrybf3jtausbnmxpgwcsz9t8qkf5pr8t5f4xyto4omjrkorpy")};
        count += build_path_aligned_to_remote(pivot);

        while (count < n)
            count += build_path_to_random();

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

    static std::atomic<bool> testnet_trigger = false;

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

            if (not testnet_trigger)
            {
                testnet_trigger = true;

                _router.loop()->call_later(5s, [this]() {
                    try
                    {
                        RouterID cpk{oxenc::from_base32z("acit6x8kwxdehpkzrpunw5nb8mf4w5u8tn3ojmxit9rpnhhhp81y")};
                        log::info(logcat, "Beginning session init to client: {}", cpk.to_network_address(false));
                        _initiate_session(
                            NetworkAddress::from_pubkey(cpk, true), [](ip_v) { log::critical(logcat, "FUCK YEAH"); });
                    }
                    catch (const std::exception& e)
                    {
                        log::critical(logcat, "Failed to parse client netaddr: {}", e.what());
                    }
                });
            }
        }
        else
            log::info(logcat, "SessionEndpoint configured to NOT publish ClientContact...");
    }

    void SessionEndpoint::resolve_ons_mappings()
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);
        auto& ons_ranges = _router.config()->network._ons_ranges;

        if (auto n_ons_ranges = ons_ranges.size(); n_ons_ranges > 0)
        {
            log::info(logcat, "SessionEndpoint resolving {} SNS addresses mapped to IP ranges", n_ons_ranges);

            for (auto itr = ons_ranges.begin(); itr != ons_ranges.end();)
            {
                resolve_ons(
                    std::move(itr->first),
                    [this, ip_range = std::move(itr->second)](std::optional<NetworkAddress> maybe_addr) {
                        if (maybe_addr)
                        {
                            log::debug(
                                logcat,
                                "Successfully resolved SNS lookup for {} mapped to IPRange:{}",
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
                                "Successfully resolved SNS lookup for {} mapped to static auth token",
                                *maybe_addr);
                            _auth_tokens.emplace(std::move(*maybe_addr), std::move(auth_token));
                        }
                        // we don't need to print a fail message, as it is logged prior to invoking with std::nullopt
                    });

                itr = ons_auths.erase(itr);
            }
        }
    }

    void SessionEndpoint::resolve_ons(std::string sns, std::function<void(std::optional<NetworkAddress>)> func)
    {
        if (not is_valid_sns(sns))
        {
            log::debug(logcat, "Invalid SNS name ({}) queried for lookup", sns);
            return func(std::nullopt);
        }

        log::debug(logcat, "Looking up SNS name {}", sns);

        auto response_handler = [sns_name = sns, hook = std::move(func)](oxen::quic::message m) mutable {
            try
            {
                if (m)
                {
                    log::critical(logcat, "Call to ResolveSNS succeeded!");

                    auto enc = ResolveSNS::deserialize_response(oxenc::bt_dict_consumer{m.body()});

                    if (auto client_addr = enc.decrypt(sns_name))
                    {
                        log::info(
                            logcat,
                            "Successfully decrypted SNS record (name: {}, address: {})",
                            sns_name,
                            client_addr->to_string());
                        return hook(std::move(client_addr));
                    }

                    log::warning(logcat, "Failed to decrypt SNS record (name: {})", sns_name);
                }
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Exception: {}", e.what());
            }

            hook(std::nullopt);
        };

        {
            Lock_t l{paths_mutex};

            for (const auto& [_, path] : _paths)
            {
                log::info(logcat, "Querying pivot:{} for name lookup (target: {})", path->pivot_rid(), sns);

                path->resolve_sns(sns, response_handler);
            }
        }
    }

    void SessionEndpoint::lookup_client_intro(RouterID remote, std::function<void(std::optional<ClientContact>)> func)
    {
        auto remote_key = dht::Key_t::derive_from_rid(remote);

        if (auto maybe_intro = _router.contact_db().get_decrypted_cc(remote))
        {
            log::info(logcat, "Decrypted ClientContact for remote (rid: {}) found locally!", remote);
            return func(std::move(maybe_intro));
        }

        log::info(
            logcat,
            "Looking up ClientContact (key: {}) for remote (rid:{})",
            remote_key,
            remote.to_network_address(false));

        auto ignore_remaining = std::make_shared<std::atomic_bool>(false);

        auto response_handler =
            [this, remote, hook = std::move(func), ignore_remaining](oxen::quic::message m) mutable {
                if (ignore_remaining->load())
                {
                    log::trace(logcat, "Dropping subsequent `find_cc` response (success: {})...", not m.is_error());
                    return;
                }
                try
                {
                    if (m)
                    {
                        log::critical(logcat, "Call to FindClientContact succeeded!");

                        auto enc = FindClientContact::deserialize_response(oxenc::bt_dict_consumer{m.body()});

                        if (auto intro = enc.decrypt(remote))
                        {
                            log::info(logcat, "Storing ClientContact for remote rid:{}", remote);
                            _router.contact_db().put_cc(std::move(enc));
                            ignore_remaining->store(true);
                            return hook(std::move(intro));
                        }

                        log::warning(logcat, "Failed to decrypt returned EncryptedClientContact!");
                    }
                    else
                    {
                        std::optional<std::string> status = std::nullopt;
                        oxenc::bt_dict_consumer btdc{m.body()};

                        if (auto s = btdc.maybe<std::string>(messages::STATUS_KEY))
                            status = s;

                        log::warning(
                            logcat, "Call to FindClientContact FAILED; reason: {}", status.value_or("<none given>"));
                    }
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Exception: {}", e.what());
                }

                hook(std::nullopt);
            };

        {
            Lock_t l{paths_mutex};

            for (const auto& [_, path] : _paths)
            {
                if (not path or not path->is_ready())
                    continue;

                log::debug(
                    logcat,
                    "Querying pivot (rid:{}) for ClientContact lookup target (rid:{})",
                    path->pivot_rid(),
                    remote);

                path->find_client_contact(remote_key, response_handler);
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

            if (not enc.verify())
                log::critical(logcat, "COULD NOT VERIFY ENCRYPTEDCLIENTCONTACT");

            if (auto decrypt = enc.decrypt(_router.local_rid()))
            {
                auto is_equal = client_contact == *decrypt;
                log::critical(logcat, "Decrypted ClientContact is {}EQUAL to the original!", is_equal ? "" : "NOT ");
            }
            else
                log::critical(logcat, "COULD NOT DECRYPT ENCRYPTEDCLIENTCONTACT");

            if (publish_client_contact(enc))
                log::info(logcat, "Successfully republished updated EncryptedClientContact!");
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
        NetworkAddress initiator,
        SessionTag tag,
        HopID remote_pivot_txid,
        std::shared_ptr<path::Path> path,
        shared_kx_data kx_data,
        bool use_tun)
    {
        bool ret = true;

        auto inbound = std::make_shared<session::InboundSession>(
            initiator,
            std::move(path),
            *this,
            std::move(remote_pivot_txid),
            std::move(tag),
            use_tun,
            std::move(kx_data));

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
                log::warning(logcat, "TUN device failed to route session (remote: {}) to local ip", session->remote());
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

        log::trace(logcat, "Publishing new EncryptedClientContact: {}", ecc.bt_payload());

        {
            Lock_t l{paths_mutex};

            for (const auto& [_, path] : _paths)
            {
                // If path-build is underway, don't use it
                if (not path or not path->is_ready())
                    continue;

                log::debug(logcat, "Publishing ClientContact on {}", path->hop_string());

                ret &= path->publish_client_contact(ecc, [](oxen::quic::message m) {
                    if (m)
                    {
                        log::critical(logcat, "Call to PublishClientContact succeeded!");
                    }
                    else
                    {
                        std::optional<std::string> status = std::nullopt;
                        try
                        {
                            oxenc::bt_dict_consumer btdc{m.body()};

                            if (auto s = btdc.maybe<std::string>(messages::STATUS_KEY))
                                status = s;
                        }
                        catch (const std::exception& e)
                        {
                            log::warning(logcat, "Exception: {}", e.what());
                        }

                        log::critical(
                            logcat, "Call to PublishClientContact FAILED; reason: {}", status.value_or("<none given>"));
                    }
                });
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

    /**

        - 'k' : next HopID
        - 'n' : symmetric nonce
        - 'x' : encrypted payload
            PATH MESSAGE ONION LAYER ('outer payload')
            - 'e' : request endpoint ('path_control')
            - 'p' : request payload
                - 'k' : next HopID
                - 'n' : symmetric nonce
                - 'x' : encrypted payload
                    PIVOT RELAY LAYER ('intermediate payload')
                    - 'e' : request endpoint ('path_control')
                    - 'p' : request payload
                        - 'k' : remote client intro pivot txid, (NOT rx)
                        - 'n' : symmetric nonce
                        - 'x' : encrypted payload
                            REMOTE CLIENT LAYER ('inner payload')
                            - 'e' : request endpoint ('session_init')
                            - 'p' : request payload
                                - 'k' : shared pubkey used to derive symmetric key
                                - 'n' : symmetric nonce
                                - 'x' : encrypted payload
                                    - 'i' : RouterID of initiator
                                    - 'p' : HopID at the pivot taken from remote ClientIntro
                                    - 's' : SessionTag for current session
                                    - 't' : Use Tun interface (bool)
                                    - 'u' : Authentication field
                                        - bt-encoded dict, values TBD
     */
    void SessionEndpoint::_make_session(
        NetworkAddress remote,
        ClientIntro remote_intro,
        std::shared_ptr<path::Path> path,
        on_session_init_hook cb,
        bool /* is_exit */)
    {
        auto tag = SessionTag::make_random();

        std::string inner_payload;
        shared_kx_data kx_data;

        // internal payload for remote client
        std::tie(inner_payload, kx_data) = InitiateSession::serialize_encrypt(
            _router.local_rid(),
            remote.router_id(),
            path->pivot_txid(),
            tag,
            remote_intro.pivot_txid,
            fetch_auth_token(remote),
            _router.using_tun_if());

        log::trace(logcat, "inner payload: {}", buffer_printer{inner_payload});

        auto pivot_payload =
            ONION::serialize_hop(remote_intro.pivot_txid.to_view(), SymmNonce::make_random(), inner_payload);
        log::trace(logcat, "pivot payload: {}", buffer_printer{pivot_payload});

        auto intermediate_payload = PATH::CONTROL::serialize("path_control", std::move(pivot_payload));
        log::trace(logcat, "intermediate payload: {}", buffer_printer{intermediate_payload});

        path->send_path_control_message(
            "path_control",
            std::move(intermediate_payload),
            [this,
             remote,
             tag,
             path,
             remote_pivot_txid = remote_intro.pivot_txid,
             hook = std::move(cb),
             session_keys = std::move(kx_data)](oxen::quic::message m) mutable {
                if (m)
                {
                    log::critical(logcat, "Call to InitiateSession succeeded!");

                    auto outbound = std::make_shared<session::OutboundSession>(
                        remote,
                        *this,
                        std::move(path),
                        std::move(remote_pivot_txid),
                        std::move(tag),
                        std::move(session_keys));

                    auto [session, _] = _sessions.insert_or_assign(std::move(remote), std::move(outbound));

                    log::info(logcat, "Outbound session to {} successfully created...", session->remote());

                    // TESTNET:
                    if (session->using_tun())
                    {
                        log::info(logcat, "Instructing lokinet TUN device to create mapped route...");
                        if (auto maybe_ip = _router.tun_endpoint()->map_session_to_local_ip(session->remote()))
                        {
                            log::info(
                                logcat,
                                "TUN device successfully routing session (remote: {}) via local ip: {}",
                                session->remote(),
                                std::holds_alternative<ipv4>(*maybe_ip) ? std::get<ipv4>(*maybe_ip).to_string()
                                                                        : std::get<ipv6>(*maybe_ip).to_string());

                            return hook(*maybe_ip);
                        }

                        log::critical(
                            logcat,
                            "Lokinet TUN failed to map route for session traffic to remote: {}",
                            session->remote());
                        // TESTNET: TODO: CLOSE THIS BISH HERE
                    }
                    else
                    {
                        log::info(logcat, "Starting TCP listener to route session traffic to backend...");
                        session->tcp_backend_listen(std::move(hook));
                    }
                }
                else
                {
                    std::optional<std::string> status = std::nullopt;
                    try
                    {
                        oxenc::bt_dict_consumer btdc{m.body()};

                        if (auto s = btdc.maybe<std::string>(messages::STATUS_KEY))
                            status = s;
                    }
                    catch (const std::exception& e)
                    {
                        log::warning(logcat, "Exception: {}", e.what());
                    }

                    log::critical(
                        logcat, "Call to InitiateSession FAILED; reason: {}", status.value_or("<none given>"));
                }
            });
        log::info(logcat, "mesage sent...");
    }

    void SessionEndpoint::_make_session_path(
        intro_set intros, NetworkAddress remote, on_session_init_hook cb, bool is_exit)
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);
        // we can recurse through this function as we remove the first pivot of the set of introductions every
        // invocation
        if (intros.empty())
        {
            log::critical(
                logcat, "Exhausted all pivots associated with remote (rid:{}); failed to make session!", remote);
            return;
        }

        // TESTNET:
        RouterID edge{oxenc::from_base32z("55fxrybf3jtausbnmxpgwcsz9t8qkf5pr8t5f4xyto4omjrkorpy")};
        bool using_hacky_bullshit{false};

        ClientIntro intro;

        for (auto itr = intros.begin(); itr != intros.end(); ++itr)
        {
            log::trace(logcat, "itr->pivot_rid: {}", itr->pivot_rid);
            if (itr->pivot_rid == edge)
            {
                using_hacky_bullshit = true;
                intro = intros.extract(itr).value();
                break;
            }
        }

        if (not using_hacky_bullshit)
        {
            intro = intros.extract(intros.begin()).value();
        }

        auto& pivot = intro.pivot_rid;

        log::info(logcat, "Initiating session path-build to remote:{} via pivot:{}", remote, pivot);

        auto maybe_hops = aligned_hops_to_remote(pivot);

        if (not maybe_hops)
        {
            log::error(logcat, "Failed to get hops for path-build to pivot:{}", pivot);
            return _make_session_path(std::move(intros), std::move(remote), std::move(cb), is_exit);
        }

        auto& hops = *maybe_hops;
        assert(pivot == hops.back().router_id());

        auto path = std::make_shared<path::Path>(_router, std::move(hops), get_weak(), true, remote.is_client());

        log::info(logcat, "Building path -> {} : {}", path->to_string(), path->hop_string());

        auto payload = build2(path);
        auto upstream = path->upstream_rid();

        if (not build3(
                std::move(upstream),
                std::move(payload),
                [this,
                 path = std::move(path),
                 remote_intro = std::move(intro),
                 intros = std::move(intros),
                 remote,
                 hook = std::move(cb),
                 is_exit](oxen::quic::message m) mutable {
                    if (m)
                    {
                        // Do not call ::add_path() or ::path_build_succeeded() here; OutboundSession constructor will
                        // take care of both path storage and logging in PathContext
                        log::critical(logcat, "PATH ESTABLISHED: {}", path->hop_string());
                        log::info(logcat, "Path build to remote:{} succeeded, initiating session!", remote);
                        return _make_session(
                            std::move(remote), std::move(remote_intro), std::move(path), std::move(hook), is_exit);
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
            log::critical(logcat, "Error sending `path_build` control message for session initiation!");
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
                [this, remote, hook = std::move(handler), is_exit, counter](std::optional<ClientContact> cc) mutable {
                    if (*counter == 0)
                        return;

                    if (cc)
                    {
                        *counter = 0;
                        log::info(logcat, "Session initiation returned client contact: {}", cc->to_string());
                        _make_session_path(std::move(cc->intros), remote, std::move(hook), is_exit);
                    }
                    else if (--*counter == 0)
                        log::warning(logcat, "Failed to initiate session at 'find_cc' (target:{})", remote.router_id());
                });
        });

        return true;
    }

    void SessionEndpoint::map_remote_to_local_addr(NetworkAddress remote, oxen::quic::Address local)
    {
        _address_map.insert_or_assign(std::move(local), std::move(remote));
    }

    void SessionEndpoint::unmap_local_addr_by_remote(const NetworkAddress& remote) { _address_map.unmap(remote); }

    void SessionEndpoint::unmap_remote_by_name(const std::string& name) { _address_map.unmap(name); }

    void SessionEndpoint::map_remote_to_local_range(NetworkAddress remote, IPRange range)
    {
        _range_map.insert_or_assign(std::move(range), std::move(remote));
    }

    void SessionEndpoint::unmap_local_range_by_remote(const NetworkAddress& remote) { _range_map.unmap(remote); }

    void SessionEndpoint::unmap_range_by_name(const std::string& name) { _range_map.unmap(name); }

}  //  namespace llarp::handlers
