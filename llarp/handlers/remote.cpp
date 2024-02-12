#include "remote.hpp"

#include <llarp/messages/common.hpp>
#include <llarp/router/router.hpp>

namespace llarp::handlers
{
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

    void RemoteHandler::lookup_name(std::string target, std::function<void(std::string res, bool success)> func)
    {
        if (not service::is_valid_name(target))
        {
            log::debug(logcat, "Invalid ONS name ({}) queried for lookup", target);
            return func(target, false);
        }

        log::debug(logcat, "{} looking up ONS name {}", name(), target);

        auto response_handler = [hook = std::move(func)](std::string response) {
            std::string name;

            try
            {
                oxenc::bt_dict_consumer btdc{response};

                if (auto status = btdc.maybe<std::string>(messages::STATUS_KEY))
                {
                    return hook(*status, false);
                }

                name = btdc.require<std::string>("E");
            }
            catch (...)
            {
                log::warning(logcat, "Exception caught parsing find_name response!");
                hook(messages::ERROR_RESPONSE, false);
            }

            hook(std::move(name), true);
        };

        {
            Lock_t l{paths_mutex};

            for (const auto& [rid, path] : _paths)
            {
                log::info(
                    logcat, "{} querying {} for name lookup (target: {})", name(), path->pivot_router_id(), target);

                path->find_name(target, response_handler);
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

    AddressVariant_t RemoteHandler::local_address() const
    {
        return _router.local_rid();
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
        /*
          * TODO: pre-config refactor, this was checking a couple things that were extremely vague
          *       these could have appeared on either [dns] or [network], but they weren't
        documented
          *       anywhere
          *
        if (k == "type" && v == "null")
        {
          m_ShouldInitTun = false;
          return true;
        }
        if (k == "exit")
        {
          m_PermitExit = IsTrueValue(v.c_str());
          return true;
        }
          */

        _dns_config = dnsConfig;
        _net_config = networkConfig;

        // TODO: this should be in router
        // if (networkConfig.endpoint_type == "null")
        // {
        //   should_init_tun = false;
        // }

        _ip_range = _net_config._local_if_range;

        if (!_ip_range.address().is_addressable())
        {
            const auto maybe = _router.net().find_free_range();
            if (not maybe.has_value())
                throw std::runtime_error("cannot find free interface range");
            _ip_range = *maybe;
        }

        _next_addr = _if_addr = _ip_range;

        _use_v6 = not _ip_range.is_ipv4();

        _if_name = _net_config._if_name;

        if (_if_name.empty())
        {
            const auto maybe = _router.net().FindFreeTun();

            if (not maybe.has_value())
                throw std::runtime_error("cannot find free interface name");

            _if_name = *maybe;
        }

        log::info(logcat, "{} set ifname to {}", name(), _if_name);

        for (const auto& addr : _net_config._addr_map)
        {
            (void)addr;
            // TODO: here is where we should map remote services and exits, but first we need
            // to unfuck the config
        }

        // if (auto* quic = GetQUICTunnel())
        // {
        // quic->listen([ifaddr = net::TruncateV6(if_addr)](std::string_view, uint16_t port) {
        //   return llarp::SockAddr{ifaddr, huint16_t{port}};
        // });
        // }
    }

    void RemoteHandler::map_remote(
        std::string /* name */,
        std::string /* token */,
        std::vector<IPRange> /* ranges */,
        std::function<void(bool, std::string)> /* result_handler */)
    {
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
    }
}  //  namespace llarp::handlers
