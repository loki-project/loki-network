#include "remote.hpp"

#include <llarp/messages/common.hpp>
#include <llarp/router/router.hpp>

namespace llarp::handlers
{
    static auto logcat = log::Cat("remote_handler");

    RemoteHandler::RemoteHandler(std::string name, Router& r)
        : path::PathHandler{r, NUM_ONS_LOOKUP_PATHS, path::DEFAULT_LEN}, _name{std::move(name)}
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

    void RemoteHandler::resolve_ons(std::string ons, std::function<void(std::optional<ClientAddress>)> func)
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
                log::warning(logcat, "Exception caught parsing find_name response!");
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

    void RemoteHandler::configure(const NetworkConfig& networkConfig, const DnsConfig& dnsConfig)
    {
        _dns_config = dnsConfig;
        _net_config = networkConfig;

        _local_range = *_net_config._local_ip_range;

        if (!_local_range.address().is_addressable())
            throw std::runtime_error("IPRange has been pre-processed and is not free!");

        _use_v6 = not _local_range.is_ipv4();
        _local_addr = *_net_config._local_addr;
        _local_ip = *_net_config._local_ip;
        _if_name = *_net_config._if_name;

        if (_if_name.empty())
            throw std::runtime_error("Interface name has been pre-processed and is not found!");

        // Remote exit mapping (TODO: move to exit::handler...? Or combine classes...?)
        for (const auto& [remote, addr] : _net_config._client_addrs)
        {
            if (remote.is_ons())
            {
                // we have the ONS name, so look up the `.loki`
                resolve_ons(remote.remote_name(), [this, addr](std::optional<ClientAddress> maybe_addr) {
                    if (maybe_addr)
                    {
                        _client_address_map.insert_or_assign(addr, *maybe_addr);
                        log::debug(
                            logcat,
                            "`ons_resolve` returned successfully -- ONS:{}, local address:{}",
                            maybe_addr,
                            addr);
                    }
                    // we already print a log::warning if failing in ::lookup_name
                });
            }
            else
            {
                // we have the '.loki`, so map it buddy boy
                _client_address_map.insert_or_assign(addr, remote);
            }
        }
    }

    bool initiate_session(RouterID remote, bool is_exit, bool is_snode)
    {
        (void)remote;
        (void)is_exit;
        (void)is_snode;
        return false;
    }

    void RemoteHandler::map_remote_to_local_addr(ClientAddress remote, oxen::quic::Address local)
    {
        _client_address_map.insert_or_assign(std::move(local), std::move(remote));
    }

    void RemoteHandler::unmap_local_addr_by_remote(const ClientAddress& remote)
    {
        _client_address_map.unmap(remote);
    }

    void RemoteHandler::unmap_remote_by_name(const std::string& name)
    {
        _client_address_map.unmap(name);
    }

    void RemoteHandler::map_remote_to_local_range(ClientAddress remote, IPRange range)
    {
        _client_range_map.insert_or_assign(std::move(range), std::move(remote));
    }

    void RemoteHandler::unmap_local_range_by_remote(const ClientAddress& remote)
    {
        _client_range_map.unmap(remote);
    }

    void RemoteHandler::unmap_range_by_name(const std::string& name)
    {
        _client_range_map.unmap(name);
    }

}  //  namespace llarp::handlers
