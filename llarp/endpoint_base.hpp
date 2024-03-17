#pragma once

#include "router_id.hpp"

#include <llarp/dns/srv_data.hpp>
#include <llarp/ev/loop.hpp>
#include <llarp/link/tunnel.hpp>
#include <llarp/service/address.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/service/types.hpp>

#include <oxen/quic.hpp>
#include <oxenc/variant.h>

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <unordered_set>

namespace llarp
{
    namespace dns
    {
        class Server;
    }

    namespace session
    {
        struct BaseSession;
    }

    // TODO: add forward declaration of TunnelManager
    //  namespace link
    //  {
    //    class TunneLManager;
    //  }

    class EndpointBase
    {
        std::unordered_set<dns::SRVData> _srv_records;

      public:
        bool _publish_introset = true;

        std::unordered_map<service::SessionTag, RouterID> _session_lookup;
        std::unordered_map<RouterID, std::shared_ptr<session::BaseSession>> _sessions;

        virtual ~EndpointBase() = default;

        bool have_session(const RouterID& rid) const
        {
            return _sessions.count(rid);
        }

        std::shared_ptr<session::BaseSession> get_session(service::SessionTag tag) const;

        std::shared_ptr<session::BaseSession> get_session(const RouterID& rid) const;

        /// add an srv record to this endpoint's descriptor
        virtual void put_srv_record(dns::SRVData srv);

        /// get dns server if we have on on this endpoint
        virtual std::shared_ptr<dns::Server> DNS() const
        {
            return nullptr;
        };

        /// called when srv data changes in some way
        virtual void srv_records_changed() = 0;

        /// Removes one SRV record that returns true given a filter function. Returns true if one
        /// SRV record was removed, false otherwise
        bool delete_srv_record_conditional(std::function<bool(const dns::SRVData&)> filter);

        /// Removes up to `n` (or exactly `n` if the optional third parameter is passed true) SRV
        /// records that return true given a filter function. Returns true if up to/exactly `n` were
        /// removed (depending on the third parameter), false otherwise
        bool delete_n_srv_records_conditional(
            size_t n, std::function<bool(const dns::SRVData&)> filter, bool exact = false);

        /// Removes all SRV records that return true given a filter function, indiscriminate of
        /// number
        bool delete_all_srv_records_conditional(std::function<bool(const dns::SRVData&)> filter);

        /// get copy of all srv records
        std::set<dns::SRVData> srv_records() const;

        /// Gets the local address for the given endpoint, service or exit node
        virtual AddressVariant_t local_address() const = 0;

        virtual link::TunnelManager* GetQUICTunnel() = 0;

        virtual const std::shared_ptr<EventLoop>& loop() = 0;

        // virtual void send_to(service::SessionTag tag, std::string payload) = 0;
    };

}  // namespace llarp
