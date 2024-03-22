#pragma once

#include "address.hpp"
#include "identity.hpp"
#include "types.hpp"

#include <llarp/dns/server.hpp>
#include <llarp/endpoint_base.hpp>
#include <llarp/net/net.hpp>
#include <llarp/path/pathhandler.hpp>
// #include <llarp/service/address.hpp>
// #include <llarp/service/identity.hpp>
// #include <llarp/service/protocol.hpp>
// #include <llarp/service/session.hpp>
#include <llarp/util/compare_ptr.hpp>
#include <llarp/vpn/egres_packet_router.hpp>

#include <oxenc/variant.h>

#include <optional>
#include <unordered_map>
#include <variant>

// minimum time between introset shifts
#ifndef MIN_SHIFT_INTERVAL
#define MIN_SHIFT_INTERVAL 5s
#endif
namespace llarp::quic
{
    class TunnelManager;
}

namespace llarp::service
{
    inline constexpr auto DEFAULT_PATH_ALIGN_TIMEOUT{30s};

    /// minimum interval for publishing introsets
    inline constexpr auto IntrosetPublishInterval = path::INTRO_PATH_SPREAD / 2;

    /// how agressively should we retry publishing introset on failure
    inline constexpr auto IntrosetPublishRetryCooldown = 1s;

    /// how aggressively should we retry looking up introsets
    inline constexpr auto IntrosetLookupCooldown = 250ms;

    /// number of unique snodes we want to talk to do to ons lookups
    inline constexpr size_t MIN_ONS_LOOKUP_ENDPOINTS{2};

    inline constexpr size_t MAX_ONS_LOOKUP_ENDPOINTS{7};

    /** Holds all local hidden service related functionality. One hidden service can be hosted per
        client or relay instance, and is managed by this object.
     */
    struct Endpoint final : public path::PathHandler, public EndpointBase, public std::enable_shared_from_this<Endpoint>
    {
        Endpoint(Router& r);
        ~Endpoint() override = default;

        std::shared_ptr<path::PathHandler> get_self() override
        {
            return shared_from_this();
        }

        std::weak_ptr<path::PathHandler> get_weak() override
        {
            return weak_from_this();
        }

        /// return true if we are ready to recv packets from the void.
        /// really should be ReadyForInboundTraffic() but the diff is HUGE and we need to rewrite
        /// this component anyways.
        bool is_ready() const;

        /// return true if our introset has expired intros
        bool IntrosetIsStale() const;

        /// construct parameters for notify hooks
        // virtual std::unordered_map<std::string, std::string>
        // NotifyParams() const;

        virtual StatusObject ExtractStatus() const;

        virtual bool Configure(const NetworkConfig& conf, const DnsConfig& dnsConf);

        void Tick(llarp_time_t now) override;

        /// return true if we have a resolvable ip address
        virtual bool HasIfAddr() const
        {
            return false;
        }

        // std::optional<SessionTag> GetBestConvoTagFor(std::variant<Address, RouterID> addr) const
        // override;

        /// get our ifaddr if it is set
        virtual huint128_t GetIfAddr() const
        {
            return {0};
        }

        /// get the exit policy for our exit if we have one
        /// override me
        virtual std::optional<net::TrafficPolicy> GetExitPolicy() const
        {
            return std::nullopt;
        };

        void reset_path_state() override;

        /// loop (via router)
        /// use when sending any data on a path
        const std::shared_ptr<EventLoop>& loop() override;

        virtual bool Start();

        std::string name() const override;

        oxen::quic::Address local_address() const override;

        // bool should_publish_intro(llarp_time_t now) const;

        // TODO:
        void build_more(size_t n = 0) override;

        void srv_records_changed() override;

        void path_died(std::shared_ptr<path::Path> p) override;

        virtual vpn::EgresPacketRouter* EgresPacketRouter()
        {
            return nullptr;
        }

        virtual vpn::NetworkInterface* GetVPNInterface()
        {
            return nullptr;
        }

        bool publish_introset(const EncryptedIntroSet& i);

        bool HandleHiddenServiceFrame(std::shared_ptr<path::Path> p, const ProtocolFrameMessage& msg);

        // virtual bool // HasServiceAddress(const AlignedBuffer< 32 >& addr) const = 0;

        // bool HandleDataMessage(
        //     std::shared_ptr<path::Path> path,
        //     const PathID_t from,
        //     std::shared_ptr<ProtocolMessage> msg);

        // virtual bool // HandleWriteIPPacket(const llarp_buffer_t& pkt,
        //                    std::function< huint128_t(void) > getFromIP) = 0;

        // bool ProcessDataMessage(std::shared_ptr<ProtocolMessage> msg);

        // TODO: move these to endpoint_base
        // "find name"
        // void lookup_name(std::string name, std::function<void(std::string, bool)> func = nullptr)
        // override;

        // "find introset?"
        // void LookupServiceAsync(
        //     std::string name,
        //     std::string service,
        //     std::function<void(std::vector<dns::SRVData>)> resultHandler) override;

        const Identity& GetIdentity() const
        {
            return _identity;
        }

        bool HandleDataDrop(std::shared_ptr<path::Path> p, const HopID& dst, uint64_t s);

        bool CheckPathIsDead(std::shared_ptr<path::Path> p, llarp_time_t latency);

        size_t RemoveAllConvoTagsFor(service::Address remote);

        // bool WantsOutboundSession(const Address&) const;

        void blacklist_snode(const RouterID& snode) override;

        virtual llarp_time_t PathAlignmentTimeout() const
        {
            return service::DEFAULT_PATH_ALIGN_TIMEOUT;
        }

        static constexpr auto DefaultPathEnsureTimeout = 2s;

        void AsyncProcessAuthMessage(std::shared_ptr<ProtocolMessage> msg, std::function<void(std::string, bool)> hook);

        void SendAuthResult(
            std::shared_ptr<path::Path> path, HopID replyPath, SessionTag tag, std::string result, bool success);

        uint64_t GenTXID();

        const std::set<RouterID>& SnodeBlacklist() const;

        /// Returns a pointer to the quic::Tunnel object handling quic connections for this
        /// endpoint. Returns nullptr if quic is not supported.
        link::TunnelManager* GetQUICTunnel() override;

      protected:
        void regen_and_publish_introset();

      private:
        bool DoNetworkIsolation(bool failed);

        virtual bool SetupNetworking()
        {
            // XXX: override me
            return true;
        }

        virtual bool IsolationFailed()
        {
            // XXX: override me
            return false;
        }

        /// return true if we are ready to do outbound and inbound traffic
        bool ReadyForNetwork() const;

      protected:
        bool ReadyToDoLookup(size_t num_paths) const;

        auto GetUniqueEndpointsForLookup() const;

        /** TESTNET: these are member attributes/functions moved to EndpointBase. This is to
            spread commonly used members amongst all types deriving from EndpointBase, like
            {Tun,Null}Endpoint. */

        // bool _publish_introset = true;

        /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

        /** TESTNET: these are member attributes/functions moved to service::Handler. This is
            a result of a separation of concerns between managing locally operated services
            vs our sessions to services operated remotely. service::Endpoint will manage the
            former, while service::Handler will manage the latter. */

        /// this MUST be called if you want to call EnsurePathTo on the given address
        // void MarkAddressOutbound(service::Address) override;

        // bool // EnsurePathTo(
        //     std::variant<Address, RouterID> addr,
        //     std::function<void(std::optional<ConvoTag>)> hook,
        //     llarp_time_t timeout) override;

        // /// return false if we have already called this function before for this
        // /// address
        // bool // EnsurePathToService(
        //     const Address remote,
        //     std::function<void(Address, OutboundContext*)> h,
        //     llarp_time_t timeoutMS = DefaultPathEnsureTimeout);
        // /// ensure a path to a service node by public key
        // bool // EnsurePathToSNode(
        //     const RouterID remote,
        //     std::function<void(const RouterID, std::shared_ptr<session::BaseSession>, ConvoTag)>
        //     h);

        /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

        Identity _identity;
        std::unique_ptr<link::TunnelManager> _tunnel_manager;

      private:
        llarp_time_t _last_introset_regen_attempt = 0s;
        std::set<RouterID> snode_blacklist;

      protected:
        friend struct EndpointUtil;
    };
}  // namespace llarp::service
