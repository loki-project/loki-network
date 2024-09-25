#pragma once

#include "router_id.hpp"

#include <llarp/dns/srv_data.hpp>
#include <llarp/ev/loop.hpp>
#include <llarp/link/tunnel.hpp>
#include <llarp/service/tag.hpp>
#include <llarp/service/types.hpp>
#include <llarp/session/map.hpp>

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

    /** TODO:
        - add protected QUICTunnel accessor
    */

    template <session::SessionType session_t, NetworkAddrType net_addr_t = NetworkAddress>
    class EndpointBase
    {
      protected:
        std::unordered_set<dns::SRVData> _srv_records;

        session_map<net_addr_t, session_t> _sessions;

      public:
        bool should_publish_introset{true};

        virtual ~EndpointBase() = default;

        std::shared_ptr<session_t> get_session(const service::SessionTag& tag) const
        {
            return _sessions.get_session(tag);
        }

        std::shared_ptr<session_t> get_session(const net_addr_t& remote) const { return _sessions.get_session(remote); }

        /// add an srv record to this endpoint's descriptor
        virtual void put_srv_record(dns::SRVData srv)
        {
            if (auto result = _srv_records.insert(std::move(srv)); result.second)
            {
                srv_records_changed();
            }
        }

        /// get dns server if we have on on this endpoint
        virtual std::shared_ptr<dns::Server> DNS() const { return nullptr; };

        /// called when srv data changes in some way
        virtual void srv_records_changed() = 0;

        /// Removes one SRV record that returns true given a filter function. Returns true if one
        /// SRV record was removed, false otherwise
        bool delete_srv_record_conditional(std::function<bool(const dns::SRVData&)> filter)
        {
            for (auto itr = _srv_records.begin(); itr != _srv_records.end(); ++itr)
            {
                if (filter(*itr))
                {
                    itr = _srv_records.erase(itr);
                    srv_records_changed();
                    return true;
                }
            }

            return false;
        }

        /// Removes up to `n` (or exactly `n` if the optional third parameter is passed true) SRV
        /// records that return true given a filter function. Returns true if up to/exactly `n` were
        /// removed (depending on the third parameter), false otherwise
        bool delete_n_srv_records_conditional(
            size_t n, std::function<bool(const dns::SRVData&)> filter, bool exact = false)

        {
            // `n` cannot be 0, or we have an insufficient amount of SRV records to return exactly `n`
            if (n == 0 or (exact and _srv_records.size() < n))
                return false;

            bool notify{false};
            size_t num_deleted{0};
            std::unordered_set<dns::SRVData> _copy{_srv_records};

            for (auto itr = _copy.begin(); itr != _copy.end(); ++itr)
            {
                //  `notify`
                //
                if (notify |= filter(*itr); notify)
                {
                    num_deleted += 1;
                    itr = _copy.erase(itr);

                    // We return early from the for-loop in one of two cases:
                    //  1) exact = true, num_deleted = n
                    //     - Return true always
                    //  2) exact = false, num_deleted = n
                    //     - Return true always
                    if (num_deleted == n)
                    {
                        _srv_records.swap(_copy);
                        srv_records_changed();
                        return notify;
                    }

                    continue;
                }
            }

            /** We only exit the for-loop in one of two cases:
                1) exact = true, num_deleted < n
                    - In this case, we return false always
                2) exact = false
                    - In this case, we return true if num_deleted > 0
                    - (num_deleted > 0) iff (notify == true), so we can treat them as identical

                exact   notify      num_deleted < n   num_deleted > 0     return
                  T       T               T               T                 F
                  T       F               T               F                 F
                  F       T               T               T                 T
                  F       F               T               F                 F
            */

            // Handles the first two rows of the above truth table
            if (exact)
                return false;

            // Handles the last two rows of the above truth table
            if (notify ^= exact; notify)
            {
                _srv_records.swap(_copy);
                srv_records_changed();
            }

            return notify;
        }

        /// Removes all SRV records that return true given a filter function, indiscriminate of
        /// number
        bool delete_all_srv_records_conditional(std::function<bool(const dns::SRVData&)> filter)
        {
            bool notify{false};

            for (auto itr = _srv_records.begin(); itr != _srv_records.end(); ++itr)
            {
                if (notify |= filter(*itr); notify)
                {
                    itr = _srv_records.erase(itr);
                    continue;
                }
            }

            if (notify)
                srv_records_changed();

            return notify;
        }

        /// get copy of all srv records
        std::set<dns::SRVData> srv_records() const { return {_srv_records.begin(), _srv_records.end()}; }

        /// Gets the local address for the given endpoint, service or exit node
        virtual oxen::quic::Address local_address() const = 0;

        virtual const std::shared_ptr<EventLoop>& loop() = 0;

        // virtual void send_to(service::SessionTag tag, std::string payload) = 0;
    };

}  // namespace llarp
