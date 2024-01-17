#pragma once

#include <llarp/auth/auth.hpp>
#include <llarp/path/pathhandler.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/util/types.hpp>

#include <unordered_map>
#include <unordered_set>

namespace llarp::service
{
    struct AsyncKeyExchange;

    struct Endpoint;

    /// context needed to initiate an outbound hidden service session
    struct OutboundContext : public llarp::path::PathBuilder, public std::enable_shared_from_this<OutboundContext>
    {
       private:
        Endpoint& ep;

        IntroSet current_intro;
        Introduction next_intro;

        const dht::Key_t location;
        const Address addr;

        ServiceInfo remote_identity;
        Introduction remote_intro;

        SessionTag current_tag;

        uint64_t update_introset_tx = 0;
        uint16_t lookup_fails = 0;
        uint16_t build_fails = 0;

        bool got_inbound_traffic = false;
        bool generated_convo_intro = false;
        bool sent_convo_intro = false;
        bool marked_bad = false;

        const std::chrono::milliseconds created_at;
        std::chrono::milliseconds last_send = 0ms;
        std::chrono::milliseconds send_timeout = path::BUILD_TIMEOUT;
        std::chrono::milliseconds connect_timeout = send_timeout * 2;
        std::chrono::milliseconds last_shift = 0ms;
        std::chrono::milliseconds last_inbound_traffic = 0ms;
        std::chrono::milliseconds last_introset_update = 0ms;
        std::chrono::milliseconds last_keep_alive = 0ms;

        void gen_intro_async_impl(std::string payload, std::function<void(std::string, bool)> func = nullptr);

       public:
        OutboundContext(const IntroSet& introSet, Endpoint* parent);

        ~OutboundContext() override;

        SessionTag get_current_tag() const
        {
            return current_tag;
        }

        void gen_intro_async(std::string payload);

        void encrypt_and_send(std::string buf);

        /// for exits
        void send_packet_to_remote(std::string buf) override;

        void send_auth_async(std::function<void(std::string, bool)> resultHandler);

        void Tick(llarp_time_t now) override;

        StatusObject ExtractStatus() const;

        void BlacklistSNode(const RouterID) override{};

        std::shared_ptr<path::PathBuilder> GetSelf() override
        {
            return shared_from_this();
        }

        std::weak_ptr<path::PathBuilder> GetWeak() override
        {
            return weak_from_this();
        }

        Address Addr() const;

        bool Stop() override;

        void HandlePathDied(std::shared_ptr<path::Path> p) override;

        /// set to true if we are updating the remote introset right now
        bool updatingIntroSet;

        /// update the current selected intro to be a new best introduction
        /// return true if we have changed intros
        bool ShiftIntroduction(bool rebuild = true);

        /// shift the intro off the current router it is using
        void ShiftIntroRouter(const RouterID remote = RouterID{});

        /// return true if we are ready to send
        bool ReadyToSend() const;

        bool ShouldBuildMore(std::chrono::milliseconds now) const override;

        /// pump internal state
        /// return true to mark as dead
        bool Pump(std::chrono::milliseconds now);

        /// return true if it's safe to remove ourselves
        bool IsDone(std::chrono::milliseconds now) const;

        bool CheckPathIsDead(std::shared_ptr<path::Path> p, std::chrono::milliseconds dlt);

        /// issues a lookup to find the current intro set of the remote service
        void UpdateIntroSet();

        void HandlePathBuilt(std::shared_ptr<path::Path> path) override;

        void HandlePathBuildTimeout(std::shared_ptr<path::Path> path) override;

        void HandlePathBuildFailedAt(std::shared_ptr<path::Path> path, RouterID hop) override;

        std::optional<std::vector<RemoteRC>> GetHopsForBuild() override;

        std::string Name() const override;

        void KeepAlive();

        bool ShouldKeepAlive(std::chrono::milliseconds now) const;

        const IntroSet& GetCurrentIntroSet() const
        {
            return current_intro;
        }

        std::chrono::milliseconds RTT() const;

       private:
        /// swap remoteIntro with next intro
        void swap_intros();
    };
}  // namespace llarp::service
