#include "session.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/nodedb.hpp>
#include <llarp/path/path.hpp>
#include <llarp/path/path_context.hpp>
#include <llarp/router/router.hpp>

#include <utility>

namespace llarp::session
{
    BaseSession::BaseSession(
        RouterID _router, Router& r, size_t hoplen, EndpointBase& parent, std::shared_ptr<auth::SessionAuthPolicy> a)
        : PathHandler{r, NUM_SESSION_PATHS, hoplen},
          _remote_router{std::move(_router)},
          _auth{a},
          _last_use{r.now()},
          _parent{parent}
    {}

    BaseSession::~BaseSession() = default;

    bool BaseSession::send_path_control_message(
        std::string method, std::string body, std::function<void(std::string)> func)
    {
        if (auto p = current_path())
            return p->send_path_control_message(std::move(method), std::move(body), std::move(func));

        return false;
    }

    bool BaseSession::send_path_data_message(std::string body)
    {
        if (auto p = current_path())
            return p->send_path_data_message(std::move(body));

        return false;
    }

    void BaseSession::path_died(std::shared_ptr<path::Path> p)
    {
        p->rebuild();
    }

    StatusObject BaseSession::ExtractStatus() const
    {
        auto obj = path::PathHandler::ExtractStatus();
        obj["lastExitUse"] = to_json(_last_use);
        auto pub = _auth->session_key().to_pubkey();
        obj["exitIdentity"] = pub.ToString();
        obj["endpoint"] = _remote_router.ToString();
        return obj;
    }

    void BaseSession::blacklist_snode(const RouterID& snode)
    {
        (void)snode;
    }

    bool BaseSession::is_path_dead(std::shared_ptr<path::Path>, llarp_time_t dlt)
    {
        return dlt >= path::ALIVE_TIMEOUT;
    }

    void BaseSession::path_build_succeeded(const RouterID& remote, std::shared_ptr<path::Path> p)
    {
        path::PathHandler::path_build_succeeded(remote, p);

        // TODO: add callback here
        if (p->obtain_exit(
                _auth->session_key(), std::is_same_v<decltype(p), ExitSession> ? 1 : 0, p->TXID().bt_encode()))
            log::info(logcat, "Asking {} for exit", _remote_router);
        else
            log::warning(logcat, "Failed to send exit request");
    }

    void BaseSession::reset_path_state()
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

    bool BaseSession::stop(bool send_close)
    {
        _running = false;

        Lock_t l{paths_mutex};

        for (auto itr = _paths.begin(); itr != _paths.end();)
        {
            auto& p = itr->second;

            dissociate_hop_ids(p);

            if (send_close)
            {
                log::info(logcat, "Sending close_exit on path {}", p->short_name());
                send_path_close(p);
            }

            itr = _paths.erase(itr);
        }

        return true;
    }

    void BaseSession::send_path_close(std::shared_ptr<path::Path> p)
    {
        if (p->close_exit(_auth->session_key(), p->TXID().bt_encode()))
            log::info(logcat, "Sent path close on path {}", p->short_name());
        else
            log::warning(logcat, "Failed to send path close on path {}", p->short_name());
    }

    bool BaseSession::is_ready() const
    {
        if (_current_hop_id.IsZero())
            return false;

        const size_t expect = (1 + (num_paths_desired / 2));

        return num_paths() >= expect;
    }

    bool BaseSession::is_expired(llarp_time_t now) const
    {
        return now > _last_use && now - _last_use > path::DEFAULT_LIFETIME;
    }

}  // namespace llarp::session
