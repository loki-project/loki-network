#pragma once

#include "session.hpp"

#include <llarp/address/address.hpp>

namespace llarp
{
    /** This class will accept any types satisfying the concepts OutboundSessionType and NetworkAddrType
            NetworkAddrType: must be inherited from NetworkAddress
            OutboundSessionType: must be inherited from BaseSession

        OutboundSessionType objects are held in shared_ptr's, and getters will return the shared_ptr
        or nullptr if not found. MAKE SURE TO CHECK ON RETURN!!
    */
    template <NetworkAddrType net_addr_t, session::SessionType session_t>
    struct session_map
    {
      protected:
        std::unordered_map<service::SessionTag, net_addr_t> _session_lookup;
        std::unordered_map<net_addr_t, std::shared_ptr<session_t>> _sessions;

      public:
        /** This functions exactly as std::unordered_map's ::insert_or_assign method. If a key equivalent
            to `local` already exists in the container, `sesh` is assigned to the mapped type. If the key
            does NOT exist, `sesh` is inserted as the value corresponding to the key `local`.

            The returned `bool` is true if the insertion took place and `false` if assignment occurred. The
            iterator is the shared_ptr that was inserted or assigned
        */
        std::pair<std::shared_ptr<session_t>, bool> insert_or_assign(net_addr_t remote, std::shared_ptr<session_t> sesh)
        {
            auto tag = sesh->tag();

            auto [_1, b1] = _session_lookup.insert_or_assign(tag, remote);
            auto [_2, b2] = _sessions.insert_or_assign(remote, std::move(sesh));

            return {_2->second, b1 & b2};
        }

        std::optional<net_addr_t> get_remote_from_tag(const service::SessionTag& tag) const
        {
            std::optional<net_addr_t> ret = std::nullopt;

            if (auto itr = _session_lookup.find(tag); itr != _session_lookup.end())
                ret = itr->second;

            return ret;
        }

        std::shared_ptr<session_t> get_session_from_remote(const net_addr_t& remote) const
        {
            std::shared_ptr<session_t> ret = nullptr;

            if (auto itr = _sessions.find(remote); itr != _sessions.end())
                ret = itr->second;

            return ret;
        }

        std::shared_ptr<session_t> get_session_from_tag(const service::SessionTag& tag) const
        {
            std::shared_ptr<session_t> ret = nullptr;

            if (auto itr = get_remote_from_tag(tag); itr != std::nullopt)
                ret = get_session_from_remote(itr->second);

            return ret;
        }

        void unmap(const service::SessionTag& tag)
        {
            if (auto it_a = _session_lookup.find(tag); it_a != _session_lookup.end())
            {
                if (auto it_b = _sessions.find(it_a->second); it_b != _sessions.end())
                {
                    _sessions.erase(it_b);
                }
                _session_lookup.erase(it_a);
            }
        }

        void unmap(const net_addr_t& local)
        {
            if (auto it_a = _sessions.find(local); it_a != _sessions.end())
            {
                auto tag = it_a->second->tag();

                if (auto it_b = _session_lookup.find(tag); it_b != _session_lookup.end())
                {
                    _session_lookup.erase(it_b);
                }
                _sessions.erase(it_a);
            }
        }

        bool have_session(const service::SessionTag& tag) const
        {
            if (auto itr = _session_lookup.find(tag); itr != _session_lookup.end())
                return have_session(itr->second);

            return false;
        }

        bool have_session(const net_addr_t& local) const
        {
            return _sessions.count(local);
        }

        std::shared_ptr<session_t> operator[](const service::SessionTag& tag)
        {
            return get_session_from_tag(tag);
        }

        std::shared_ptr<session_t> operator[](const net_addr_t& local)
        {
            return get_session_from_remote(local);
        }
    };
}  //  namespace llarp
