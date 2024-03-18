#include "auth.hpp"

#include <llarp/router/router.hpp>
#include <llarp/service/endpoint.hpp>

namespace llarp::auth
{
    static auto logcat = log::Cat("rpc.auth");

    RPCAuthPolicy::RPCAuthPolicy(
        Router& r,
        std::string url,
        std::string method,
        std::unordered_set<llarp::service::Address> whitelist_addrs,
        std::unordered_set<std::string> whitelist_tokens,
        std::shared_ptr<oxenmq::OxenMQ> lmq,
        std::shared_ptr<service::Endpoint> endpoint)
        : AuthPolicy{r},
          _url{std::move(url)},
          _method{std::move(method)},
          _whitelist{std::move(whitelist_addrs)},
          _static_tokens{std::move(whitelist_tokens)},
          _omq{std::move(lmq)},
          _ep{std::move(endpoint)}
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

    bool RPCAuthPolicy::auth_async_pending(service::SessionTag tag) const
    {
        return _pending_sessions.count(tag) > 0;
    }

    void RPCAuthPolicy::authenticate_async(
        std::shared_ptr<llarp::service::ProtocolMessage> msg, std::function<void(std::string, bool)> hook)
    {
        service::SessionTag tag = msg->tag;
        _pending_sessions.insert(tag);
        const auto from = msg->sender.address();
        auto reply = _ep->loop()->make_caller([this, tag, hook](std::string code, bool success) {
            _pending_sessions.erase(tag);
            hook(code, success);
        });
        if (_whitelist.count(from))
        {
            // explicitly whitelisted source
            reply("explicitly whitelisted", true);
            return;
        }

        if (msg->proto != llarp::service::ProtocolType::Auth)
        {
            // not an auth message, reject
            reply("protocol error", false);
            return;
        }

        std::string payload{(char*)msg->payload.data(), msg->payload.size()};

        if (_static_tokens.count(payload))
        {
            reply("explicitly whitelisted", true);
            return;
        }

        if (not _omq_conn.has_value())
        {
            if (_static_tokens.empty())
            {
                // we don't have a connection to the backend so it's failed
                reply("remote has no connection to auth backend", false);
            }
            else
            {
                // static auth mode
                reply("access not permitted", true);
            }
            return;
        }

        const auto authinfo = msg->encode_auth_info();
        std::string_view metainfo{authinfo.data(), authinfo.size()};
        // call method with 2 parameters: metainfo and userdata
        _omq->request(
            *_omq_conn,
            _method,
            [self = shared_from_this(), reply = std::move(reply)](bool success, std::vector<std::string> data) {
                AuthResult result{AuthCode::FAILED, "no reason given"};

                if (success and not data.empty())
                {
                    if (const auto maybe = parse_auth_code(data[0]))
                    {
                        result.code = *maybe;
                    }
                    if (result.code == AuthCode::ACCEPTED)
                    {
                        result.reason = "OK";
                    }
                    if (data.size() > 1)
                    {
                        result.reason = data[1];
                    }
                }

                reply(result.reason, success);
            },
            metainfo,
            payload);
    }
}  // namespace llarp::auth
