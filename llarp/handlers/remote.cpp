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
        (void)n;
    }

    bool RemoteHandler::initiate_session_to_remote(const RouterID& remote)
    {
        if (have_session(remote))
            return false;

        return true;
    }

    void RemoteHandler::lookup_name(std::string ons, std::function<void(std::optional<ClientAddress>)> func)
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
                return hook(client_addr);
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
                log::info(logcat, "{} querying {} for name lookup (target: {})", name(), path->pivot_router_id(), ons);

                path->find_name(ons, response_handler);
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

    void RemoteHandler::Tick(llarp_time_t now)
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
                lookup_name(remote.remote_name(), [this, addr](std::optional<ClientAddress> maybe_addr) {
                    if (maybe_addr)
                    {
                        _client_address_map.map_remote_to_local(*maybe_addr, addr);
                        log::debug(
                            logcat, "`find_name` returned successfully -- ONS:{}, local address:{}", *maybe_addr, addr);
                    }
                    // we already print a log::warning if failing in ::lookup_name
                });
            }
            else
            {
                // we have the '.loki`, so map it buddy boy
                _client_address_map.map_remote_to_local(remote, addr);
            }
        }

        _configure();
    }

    // void RemoteHandler::map_remote(
    //     std::string name,
    //     std::string token,
    //     std::vector<IPRange> ranges,
    //     std::function<void(bool, std::string)> result_handler)
    // {
    // if (ranges.empty())
    // {
    //   result_handler(false, "no ranges provided");
    //   return;
    // }

    // lookup_name(
    //     name,
    //     [ptr = std::static_pointer_cast<Handler>(get_self()),
    //      name,
    //      auth = auth::AuthInfo{token},
    //      ranges,
    //      result_handler,
    //      poker = router().route_poker()](std::string response, bool success) mutable {
    //       if (not success)
    //       {
    //         result_handler(false, "Exit {} not found!"_format(response));
    //         return;
    //       }

    //       if (auto saddr = service::Address(); saddr.FromString(result))
    //       {
    //       ptr->SetAuthInfoForEndpoint(saddr, auth);
    //       ptr->MarkAddressOutbound(saddr);

    //       auto result = ptr->EnsurePathToService(
    //           saddr,
    //           [ptr, name, name_result, ranges, result_handler, poker](
    //               auto addr, OutboundContext* ctx) {
    //             if (ctx == nullptr)
    //             {
    //               result_handler(
    //                   false, "could not establish flow to {} ({})"_format(name_result,
    //                   name));
    //               return;
    //             }

    //             // make a lambda that sends the reply after doing auth
    //             auto apply_result = [ptr, poker, addr, result_handler, ranges](
    //                                     std::string result, bool success) {
    //               if (success)
    //               {
    //                 for (const auto& range : ranges)
    //                   ptr->MapExitRange(range, addr);

    //                 if (poker)
    //                   poker->put_up();
    //               }

    //               result_handler(success, result);
    //             };

    //             ctx->send_auth_async(apply_result);
    //           },
    //           ptr->PathAlignmentTimeout());

    //       if (not result)
    //         result_handler(false, "Could not build path to {} ({})"_format(name_result,
    //         name));
    //       }
    //     });
    // }

    void RemoteHandler::map_remote_to_local_addr(ClientAddress remote, oxen::quic::Address local)
    {
        _client_address_map.map_remote_to_local(remote, local);
    }

    void RemoteHandler::unmap_local_addr_by_remote(ClientAddress remote)
    {
        _client_address_map.unmap_by_remote(remote);
    }

    void RemoteHandler::unmap_remote_by_name(std::string name)
    {
        _client_address_map.unmap_by_name(name);
    }

    void RemoteHandler::map_remote_to_local_range(ClientAddress remote, IPRange range)
    {
        _client_range_map.map_remote_to_local(remote, range);
    }

    void RemoteHandler::unmap_local_range_by_remote(ClientAddress remote)
    {
        _client_range_map.unmap_by_remote(remote);
    }

    void RemoteHandler::unmap_range_by_name(std::string name)
    {
        _client_range_map.unmap_by_name(name);
    }

}  //  namespace llarp::handlers
