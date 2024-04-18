#include "remote.hpp"

#include <llarp/link/contacts.hpp>
#include <llarp/messages/path.hpp>
#include <llarp/messages/session.hpp>
#include <llarp/router/router.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("remote_handler");

    RemoteHandler::RemoteHandler(Router& r) : path::PathHandler{r, NUM_ONS_LOOKUP_PATHS, path::DEFAULT_LEN}
    {}

    RemoteHandler::~RemoteHandler() = default;

    void RemoteHandler::build_more(size_t n)
    {
        size_t count{0};
        log::debug(logcat, "RemoteHandler building {} paths to random remotes (needed: {})", n, NUM_ONS_LOOKUP_PATHS);

        for (size_t i = 0; i < n; ++i)
        {
            count += build_path_to_random();
        }

        if (count == n)
            log::debug(logcat, "RemoteHandler successfully initiated {} path-builds", n);
        else
            log::warning(logcat, "RemoteHandler only initiated {} path-builds (needed: {})", count, n);
    }

    void RemoteHandler::resolve_ons_mappings()
    {
        auto& ons_ranges = _router.config()->network._ons_ranges;

        for (auto itr = ons_ranges.begin(); itr != ons_ranges.end();)
        {
            resolve_ons(
                std::move(itr->first),
                [this, ip_range = std::move(itr->second)](std::optional<NetworkAddress> maybe_addr) {
                    if (maybe_addr)
                    {
                        log::debug(logcat, "Successfully resolved ONS lookup for {}", *maybe_addr);
                        map_remote_to_local_range(std::move(*maybe_addr), std::move(ip_range));
                    }
                    // we don't need to print a fail message, as it is logged prior to invoking with std::nullopt
                });

            itr = ons_ranges.erase(itr);
        }
    }

    void RemoteHandler::resolve_ons(std::string ons, std::function<void(std::optional<NetworkAddress>)> func)
    {
        if (not service::is_valid_ons(ons))
        {
            log::debug(logcat, "Invalid ONS name ({}) queried for lookup", ons);
            return func(std::nullopt);
        }

        log::debug(logcat, "{} looking up ONS name {}", name(), ons);

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
                log::info(
                    logcat, "{} querying pivot:{} for name lookup (target: {})", name(), path->pivot_router_id(), ons);

                path->resolve_ons(ons, response_handler);
            }
        }
    }

    void RemoteHandler::lookup_intro(
        RouterID remote, bool is_relayed, uint64_t order, std::function<void(std::optional<service::IntroSet>)> func)
    {
        if (auto maybe_intro = _router.contacts().get_decrypted_introset(remote))
        {
            log::debug(logcat, "{} found decrypted introset locally for remote:{}", name(), remote);
            return func(std::move(maybe_intro));
        }

        log::debug(logcat, "{} looking up introset for remote:{}", name(), remote);
        auto remote_key = dht::Key_t::derive_from_rid(remote);

        auto response_handler = [this, remote, hook = std::move(func)](std::string response) {
            if (auto encrypted = service::EncryptedIntroSet::construct(response);
                auto intro = encrypted->decrypt(remote))
            {
                log::debug(logcat, "Storing introset for remote:{}", remote);
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
                    logcat,
                    "{} querying pivot:{} for introset lookup (target: {})",
                    name(),
                    path->pivot_router_id(),
                    remote);

                path->find_intro(remote_key, is_relayed, order, response_handler);
            }
        }
    }

    void RemoteHandler::lookup_remote_srv(
        std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler)
    {
        (void)name;
        (void)service;
        (void)handler;
    }

    const std::shared_ptr<EventLoop>& RemoteHandler::loop()
    {
        return _router.loop();
    }

    void RemoteHandler::Tick(std::chrono::milliseconds now)
    {
        (void)now;
    }

    void RemoteHandler::srv_records_changed()
    {
        // TODO: Investigate the usage or the term exit RE: service nodes acting as exits
        // ^^ lol
    }

    void RemoteHandler::configure()
    {
        auto dns_config = _router.config()->dns;
        auto net_config = _router.config()->network;

        _local_range = *net_config._local_ip_range;

        if (!_local_range.address().is_addressable())
            throw std::runtime_error("IPRange has been pre-processed and is not free!");

        _use_v6 = not _local_range.is_ipv4();
        _local_addr = *net_config._local_addr;
        _local_ip = *net_config._local_ip;
        _if_name = *net_config._if_name;

        if (_if_name.empty())
            throw std::runtime_error("Interface name has been pre-processed and is not found!");

        for (auto& [addr, range] : net_config._exit_ranges)
        {
            map_remote_to_local_range(addr, range);
        }
    }

    void RemoteHandler::make_session(NetworkAddress remote, std::shared_ptr<path::Path> path, bool is_exit)
    {
        auto auth = std::make_shared<auth::SessionAuthPolicy>(_router, not remote.is_client(), is_exit);
        auto tag = service::SessionTag::make_random();

        path->send_path_control_message(
            "session_init",
            InitiateSession::serialize_encrypt(
                _router.local_rid(), remote.router_id(), tag, path->terminal_txid(), auth->fetch_auth_token()),
            [this, remote, tag, path, auth](std::string response) {
                // TODO: this will change after defining ::handle_session_init() function
                if (response == messages::OK_RESPONSE)
                {
                    auto outbound =
                        session::OutboundSession{remote, *this, std::move(path), std::move(tag), std::move(auth)};

                    // emplace outbound in session map

                    // yadda yadda

                    // yay session is made
                }
            });
    }

    void RemoteHandler::make_session_path(service::IntroductionSet intros, NetworkAddress remote, bool is_exit)
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

        log::info(logcat, "Initiating session path-build to remote:{} via pivot:{}", remote, pivot);

        auto maybe_hops = aligned_hops_to_remote(pivot);

        if (not maybe_hops)
        {
            log::error(logcat, "Failed to get hops for path-build to pivot:{}", pivot);
            return;
        }

        auto& hops = *maybe_hops;
        assert(pivot == hops.back().router_id());

        auto path = std::make_shared<path::Path>(_router, hops, get_weak(), true);

        log::info(logcat, "{} building path -> {} : {}", name(), path->to_string(), path->HopsString());

        auto payload = build2(path);

        if (not build3(
                path->upstream(), std::move(payload), [this, path, intros, remote, is_exit](oxen::quic::message m) {
                    if (m)
                    {
                        log::info(logcat, "Path build to remote:{} succeeded, initiating session!", remote);
                        return make_session(std::move(remote), std::move(path), is_exit);
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
                    make_session_path(std::move(intros), std::move(remote), is_exit);
                }))
        {
            log::critical(logcat, "Error sending path_build control message for session initiation!");
        }
    }

    bool RemoteHandler::initiate_session(NetworkAddress remote, bool is_exit)
    {
        if (is_exit and not remote.is_client())
            throw std::runtime_error{"Cannot initiate exit session to remote service node!"};

        auto counter = std::make_shared<size_t>(NUM_ONS_LOOKUP_PATHS);

        _router.loop()->call([this, remote, is_exit, counter]() {
            lookup_intro(
                remote.router_id(), false, 0, [this, remote, is_exit, counter](std::optional<service::IntroSet> intro) {
                    // already have a successful return
                    if (*counter == 0)
                        return;

                    if (intro)
                    {
                        *counter = 0;
                        log::info(logcat, "Session initiation returned successful 'lookup_intro'...");
                        make_session_path(std::move(intro->intros), remote, is_exit);
                    }
                    else if (--*counter == 0)
                    {
                        log::warning(logcat, "Failed to initiate session at 'lookup_intro' (target:{})", remote);
                    }
                });
        });

        return true;
    }

    void RemoteHandler::map_remote_to_local_addr(NetworkAddress remote, oxen::quic::Address local)
    {
        _address_map.insert_or_assign(std::move(local), std::move(remote));
    }

    void RemoteHandler::unmap_local_addr_by_remote(const NetworkAddress& remote)
    {
        _address_map.unmap(remote);
    }

    void RemoteHandler::unmap_remote_by_name(const std::string& name)
    {
        _address_map.unmap(name);
    }

    void RemoteHandler::map_remote_to_local_range(NetworkAddress remote, IPRange range)
    {
        _range_map.insert_or_assign(std::move(range), std::move(remote));
    }

    void RemoteHandler::unmap_local_range_by_remote(const NetworkAddress& remote)
    {
        _range_map.unmap(remote);
    }

    void RemoteHandler::unmap_range_by_name(const std::string& name)
    {
        _range_map.unmap(name);
    }

}  //  namespace llarp::handlers
