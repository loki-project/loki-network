#include "auth.hpp"

#include <llarp/router/router.hpp>

namespace llarp::auth
{
    static auto logcat = log::Cat("rpc.auth");

    RPCAuthPolicy::RPCAuthPolicy(
        Router& r,
        std::string url,
        std::string method,
        std::unordered_set<NetworkAddress> whitelist_addrs,
        std::unordered_set<std::string> whitelist_tokens,
        std::shared_ptr<oxenmq::OxenMQ> lmq)
        : AuthPolicy{r},
          _url{std::move(url)},
          _method{std::move(method)},
          _whitelist{std::move(whitelist_addrs)},
          _static_tokens{std::move(whitelist_tokens)},
          _omq{std::move(lmq)}
    {}

    void RPCAuthPolicy::start()
    {
        if (_url.empty() or _method.empty())
            return;

        _omq->connect_remote(
            oxenmq::address{_url},
            [self = shared_from_this()](oxenmq::ConnectionID c) {
                self->_omq_conn = std::move(c);
                log::info(logcat, "OMQ connected to endpoint auth server");
            },
            [self = shared_from_this()](oxenmq::ConnectionID, std::string_view fail) {
                log::warning(logcat, "OMQ failed to connect to endpoint auth server: {}", fail);
                self->_router.loop()->call_later(1s, [self] { self->start(); });
            });
    }

}  // namespace llarp::auth
