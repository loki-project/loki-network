#include "session.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/formattable.hpp>

#include <utility>

namespace llarp::session
{
    static auto logcat = log::Cat("session.base");

    OutboundSession::OutboundSession(
        RouterID _remote,
        handlers::RemoteHandler& parent,
        std::shared_ptr<path::Path> path,
        service::SessionTag _t,
        std::shared_ptr<auth::SessionAuthPolicy> a)
        : PathHandler{parent._router, NUM_SESSION_PATHS},
          _remote_router{std::move(_remote)},
          _auth{std::move(a)},
          _current_path{std::move(path)},
          _current_hop_id{_current_path->intro.hop_id},
          _tag{std::move(_t)},
          _last_use{_router.now()},
          _parent{parent},
          _is_exit_service{_auth->is_exit_service()},
          _is_snode_service{_auth->is_snode_service()},
          _prefix{
              _is_exit_service        ? PREFIX::EXIT
                  : _is_snode_service ? PREFIX::SNODE
                                      : PREFIX::LOKI}
    {
        // These can both be false but CANNOT both be true
        if (_is_exit_service & _is_snode_service)
            throw std::runtime_error{"Cannot create OutboundSession for a remote exit and remote service!"};
    }

    OutboundSession::~OutboundSession() = default;

    bool OutboundSession::send_path_control_message(
        std::string method, std::string body, std::function<void(std::string)> func)
    {
        if (auto p = current_path())
            return p->send_path_control_message(std::move(method), std::move(body), std::move(func));

        return false;
    }

    bool OutboundSession::send_path_data_message(std::string body)
    {
        if (auto p = current_path())
            return p->send_path_data_message(std::move(body));

        return false;
    }

    void OutboundSession::path_died(std::shared_ptr<path::Path> p)
    {
        p->rebuild();
    }

    nlohmann::json OutboundSession::ExtractStatus() const
    {
        auto obj = path::PathHandler::ExtractStatus();
        obj["lastExitUse"] = to_json(_last_use);
        auto pub = _auth->session_key().to_pubkey();
        obj["exitIdentity"] = pub.to_string();
        obj["endpoint"] = _remote_router.to_string();
        return obj;
    }

    void OutboundSession::blacklist_snode(const RouterID& snode)
    {
        (void)snode;
    }

    bool OutboundSession::is_path_dead(std::shared_ptr<path::Path>, std::chrono::milliseconds dlt)
    {
        return dlt >= path::ALIVE_TIMEOUT;
    }

    void OutboundSession::path_build_succeeded(const RouterID& remote, std::shared_ptr<path::Path> p)
    {
        path::PathHandler::path_build_succeeded(remote, p);

        // TODO: add callback here
        if (p->obtain_exit(_auth->session_key(), _is_snode_service ? 1 : 0, p->TXID().to_string()))
            log::info(logcat, "Asking {} for exit", _remote_router);
        else
            log::warning(logcat, "Failed to send exit request");
    }

    void OutboundSession::reset_path_state()
    {
        // TODO: should we be closing exits on internal state reset?
        auto sendExitClose = [&](const std::shared_ptr<path::Path> p) {
            // const static auto roles = llarp::path::ePathRoleExit | llarp::path::ePathRoleSVC;
            (void)p;

            // if (p->SupportsAnyRoles(roles))
            // {
            //   log::info(logcat, "{} closing exit path", p->name());
            //   if (p->close_exit(_session_key, p->TXID().bt_encode()))
            //     p->ClearRoles(roles);
            //   else
            //     llarp::LogWarn(p->name(), " failed to send exit close message");
            // }
        };

        for_each_path(sendExitClose);
        path::PathHandler::reset_path_state();
    }

    bool OutboundSession::stop(bool send_close)
    {
        _running = false;

        Lock_t l{paths_mutex};

        for (auto itr = _paths.begin(); itr != _paths.end();)
        {
            auto& p = itr->second;

            dissociate_hop_ids(p);

            if (send_close)
            {
                log::info(logcat, "Sending close_exit on path {}", p->to_string());
                send_path_close(p);
            }

            itr = _paths.erase(itr);
        }

        return true;
    }

    void OutboundSession::build_more(size_t n)
    {
        size_t count{0};
        log::debug(logcat, "OutboundSession building {} paths to random remotes (needed: {})", n, NUM_ONS_LOOKUP_PATHS);

        for (size_t i = 0; i < n; ++i)
        {
            count += build_path_to_random();
        }

        if (count == n)
            log::debug(logcat, "OutboundSession successfully initiated {} path-builds", n);
        else
            log::warning(logcat, "OutboundSession only initiated {} path-builds (needed: {})", count, n);
    }

    void OutboundSession::send_path_close(std::shared_ptr<path::Path> p)
    {
        if (p->close_exit(_auth->session_key(), p->TXID().to_string()))
            log::info(logcat, "Sent path close on path {}", p->to_string());
        else
            log::warning(logcat, "Failed to send path close on path {}", p->to_string());
    }

    bool OutboundSession::is_ready() const
    {
        if (_current_hop_id.is_zero())
            return false;

        const size_t expect = (1 + (num_paths_desired / 2));

        return num_paths() >= expect;
    }

    bool OutboundSession::is_expired(std::chrono::milliseconds now) const
    {
        return now > _last_use && now - _last_use > path::DEFAULT_LIFETIME;
    }

}  // namespace llarp::session
