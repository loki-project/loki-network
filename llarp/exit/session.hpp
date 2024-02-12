#pragma once

#include <llarp/constants/path.hpp>
#include <llarp/net/ip_packet_old.hpp>
#include <llarp/path/pathbuilder.hpp>
#include <llarp/service/protocol_type.hpp>

#include <deque>
#include <queue>

namespace llarp
{
    class EndpointBase;

    namespace link
    {
        class TunnelManager;
    }

    namespace exit
    {
        struct BaseSession;

        using SessionReadyFunc = std::function<void(std::shared_ptr<BaseSession>)>;

        /// a persisting exit session with an exit router
        struct BaseSession : public llarp::path::PathBuilder, public std::enable_shared_from_this<BaseSession>
        {
            BaseSession(
                const llarp::RouterID& exitRouter,
                std::function<bool(const llarp_buffer_t&)> writepkt,
                Router* r,
                size_t numpaths,
                size_t hoplen,
                EndpointBase* parent);

            ~BaseSession() override;

            std::shared_ptr<path::PathSet> GetSelf() override
            {
                return shared_from_this();
            }

            std::weak_ptr<path::PathSet> GetWeak() override
            {
                return weak_from_this();
            }

            void BlacklistSNode(const RouterID snode) override;

            util::StatusObject ExtractStatus() const;

            void ResetInternalState() override;

            bool UrgentBuild(llarp_time_t) const override;

            void HandlePathDied(std::shared_ptr<path::Path> p) override;

            bool CheckPathDead(std::shared_ptr<path::Path> p, llarp_time_t dlt);

            std::optional<std::vector<RemoteRC>> GetHopsForBuild() override;

            bool ShouldBuildMore(llarp_time_t now) const override;

            void HandlePathBuilt(std::shared_ptr<path::Path> p) override;

            /// flush upstream to exit via paths
            bool FlushUpstream();

            /// flush downstream to user via tun
            void FlushDownstream();

            path::PathRole GetRoles() const override
            {
                return path::ePathRoleExit;
            }

            /// send close and stop session
            bool Stop() override;

            bool IsReady() const;

            const llarp::RouterID Endpoint() const
            {
                return exit_router;
            }

            std::optional<PathID_t> CurrentPath() const
            {
                if (_current_path.IsZero())
                    return std::nullopt;
                return _current_path;
            }

            bool IsExpired(llarp_time_t now) const;

            bool LoadIdentityFromFile(const char* fname);

            void AddReadyHook(SessionReadyFunc func);

           protected:
            llarp::RouterID exit_router;
            llarp::SecretKey exit_key;
            std::function<bool(const llarp_buffer_t&)> packet_write_func;

            bool HandleTrafficDrop(std::shared_ptr<path::Path> p, const llarp::PathID_t& path, uint64_t s);

            bool HandleGotExit(std::shared_ptr<path::Path> p, llarp_time_t b);

            bool HandleTraffic(
                std::shared_ptr<path::Path> p, const llarp_buffer_t& buf, uint64_t seqno, service::ProtocolType t);

           private:
            std::set<RouterID> snode_blacklist;

            PathID_t _current_path;

            // uint64_t _counter;
            llarp_time_t _last_use;

            std::vector<SessionReadyFunc> _pending_callbacks;
            // const bool _bundle_RC;
            EndpointBase* const _parent;

            void CallPendingCallbacks(bool success);
        };

        struct ExitSession final : public BaseSession
        {
            ExitSession(
                const llarp::RouterID& snodeRouter,
                std::function<bool(const llarp_buffer_t&)> writepkt,
                Router* r,
                size_t numpaths,
                size_t hoplen,
                EndpointBase* parent)
                : BaseSession{snodeRouter, writepkt, r, numpaths, hoplen, parent}
            {}

            ~ExitSession() override = default;

            std::string Name() const override;

            void send_packet_to_remote(std::string buf) override;
        };

        struct SNodeSession final : public BaseSession
        {
            SNodeSession(
                const llarp::RouterID& snodeRouter,
                std::function<bool(const llarp_buffer_t&)> writepkt,
                Router* r,
                size_t numpaths,
                size_t hoplen,
                bool useRouterSNodeKey,
                EndpointBase* parent);

            ~SNodeSession() override = default;

            std::string Name() const override;

            void send_packet_to_remote(std::string buf) override;
        };

    }  // namespace exit
}  // namespace llarp
