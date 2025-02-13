#pragma once

#include "session.hpp"

#include <llarp/address/address.hpp>
#include <llarp/util/thread/threading.hpp>

namespace llarp
{
    // TESTNET: TODO: revisit this later; if we never need NetworkAddr as a key, just use tag

    /** This class will accept any types satisfying the concepts SessionType and NetworkAddrType
            NetworkAddrType: must be inherited from NetworkAddress
            SessionType: must be inherited from BaseSession

        OutboundSessionType objects are held in shared_ptr's, and getters will return the shared_ptr
        or nullptr if not found. MAKE SURE TO CHECK ON RETURN!!
    */
    template <concepts::NetworkAddrType net_addr_t, concepts::SessionType session_t>
    struct session_map
    {
      protected:
        std::unordered_map<session_tag, net_addr_t> _session_lookup;
        std::unordered_map<net_addr_t, std::shared_ptr<session_t>> _sessions;

        using Lock_t = util::NullLock;
        mutable util::NullMutex session_mutex;

      public:
        /** Returns the number of sessions currently mapped to remote addresses
         */
        size_t count() const
        {
            Lock_t l{session_mutex};
            return _sessions.size();
        }

        /** Called by owning object to apply a callback to every session currently mapped
         */
        void for_each(std::function<void(std::shared_ptr<session_t>&)> hook)
        {
            Lock_t l{session_mutex};

            for (auto& [_, s] : _sessions)
            {
                if (s->is_active())
                    hook(s);
            }
        }

        /** Called by owning object to tick OutboundSessions. InboundSession objects are not PathHandlers, so they have
            no concept of tick functionality
         */
        void tick_outbounds(std::chrono::milliseconds now)
        {
            Lock_t l{session_mutex};

            for (auto& [_, s] : _sessions)
            {
                if (s->is_outbound() && s->is_active())
                    std::dynamic_pointer_cast<session::OutboundSession>(s)->tick(now);
            }
        }

        /** Called by owning object to stop all Sessions, then clear the map.
         */
        void stop_sessions(bool send_close = false)
        {
            Lock_t l{session_mutex};

            if (send_close)
            {
                for (auto& [_, s] : _sessions)
                {
                    s->stop_session(send_close);
                }
            }

            _sessions.clear();
        }

        /** This functions exactly as std::unordered_map's ::insert_or_assign method. If a key equivalent
            to `remote` already exists in the container, `sesh` is assigned to the mapped type. If the key
            does NOT exist, `sesh` is inserted as the value corresponding to the key `remote`.

            The returned `bool` is true if the insertion took place and `false` if assignment occurred. The
            iterator is the shared_ptr that was inserted or assigned
        */
        std::pair<std::shared_ptr<session_t>, bool> insert_or_assign(net_addr_t remote, std::shared_ptr<session_t> sesh)
        {
            Lock_t l{session_mutex};

            auto tag = sesh->tag();

            auto [_1, b1] = _session_lookup.insert_or_assign(tag, remote);
            auto [_2, b2] = _sessions.insert_or_assign(remote, std::move(sesh));

            return {_2->second, b1 & b2};
        }

        std::optional<net_addr_t> get_remote(const session_tag& tag) const
        {
            Lock_t l{session_mutex};

            std::optional<net_addr_t> ret = std::nullopt;

            if (auto itr = _session_lookup.find(tag); itr != _session_lookup.end())
                ret = itr->second;

            return ret;
        }

        std::shared_ptr<session_t> get_session(const net_addr_t& remote) const
        {
            Lock_t l{session_mutex};

            std::shared_ptr<session_t> ret = nullptr;

            if (auto itr = _sessions.find(remote); itr != _sessions.end())
                ret = itr->second;

            return ret;
        }

        std::shared_ptr<session_t> get_session(const session_tag& tag) const
        {
            Lock_t l{session_mutex};

            std::shared_ptr<session_t> ret = nullptr;

            if (auto remote = get_remote(tag); remote != std::nullopt)
                ret = get_session(*remote);

            return ret;
        }

        void unmap(const session_tag& tag)
        {
            Lock_t l{session_mutex};

            if (auto it_a = _session_lookup.find(tag); it_a != _session_lookup.end())
            {
                if (auto it_b = _sessions.find(it_a->second); it_b != _sessions.end())
                    _sessions.erase(it_b);

                _session_lookup.erase(it_a);
            }
        }

        void unmap(const net_addr_t& remote)
        {
            Lock_t l{session_mutex};

            if (auto it_a = _sessions.find(remote); it_a != _sessions.end())
            {
                auto tag = it_a->second->tag();

                if (auto it_b = _session_lookup.find(tag); it_b != _session_lookup.end())
                    _session_lookup.erase(it_b);

                _sessions.erase(it_a);
            }
        }

        bool have_session(const session_tag& tag) const
        {
            Lock_t l{session_mutex};

            if (auto itr = _session_lookup.find(tag); itr != _session_lookup.end())
                return have_session(itr->second);

            return false;
        }

        bool have_session(const net_addr_t& remote) const
        {
            Lock_t l{session_mutex};

            return _sessions.count(remote);
        }

        std::shared_ptr<session_t> operator[](const session_tag& tag) { return get_session(tag); }

        std::shared_ptr<session_t> operator[](const net_addr_t& remote) { return get_session(remote); }
    };
}  //  namespace llarp
