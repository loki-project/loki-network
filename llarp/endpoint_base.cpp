#include "endpoint_base.hpp"

namespace llarp
{
    void EndpointBase::put_srv_record(dns::SRVData srv)
    {
        if (auto result = _srv_records.insert(std::move(srv)); result.second)
        {
            srv_records_changed();
        }
    }

    bool EndpointBase::delete_srv_record_conditional(std::function<bool(const dns::SRVData&)> filter)
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

    bool EndpointBase::delete_n_srv_records_conditional(
        size_t n, std::function<bool(const dns::SRVData&)> filter, bool exact)
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

    bool EndpointBase::delete_all_srv_records_conditional(std::function<bool(const dns::SRVData&)> filter)
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

    std::set<dns::SRVData> EndpointBase::srv_records() const
    {
        return {_srv_records.begin(), _srv_records.end()};
    }

    std::shared_ptr<session::BaseSession> EndpointBase::get_session(service::SessionTag tag) const
    {
        if (auto itr = _session_lookup.find(tag); itr != _session_lookup.end())
            return get_session(itr->second);

        return nullptr;
    }

    std::shared_ptr<session::BaseSession> EndpointBase::get_session(const RouterID& rid) const
    {
        if (auto itr = _sessions.find(rid); itr != _sessions.end())
            return itr->second;

        return nullptr;
    }

}  // namespace llarp
