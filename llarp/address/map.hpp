#pragma once

#include "address.hpp"
#include "ip_range.hpp"
#include "types.hpp"

#include <llarp/util/formattable.hpp>
#include <llarp/util/thread/threading.hpp>

namespace llarp
{
    /** TODO:
        - if libquic Address is never used for this templated class, then either:
            - this map can potentially be made (mostly) constexpr
            - a new map just for IP addresses can be made fully constexpr
    */

    /** This class will accept any types satisfying the concepts LocalAddrType and RemoteAddrType
            LocalAddrType: oxen::quic::Address, IPRange, or ip_v (ipv{4,6} variant)
            NetworkAddrType: must be inherited from NetworkAddress
    */
    template <LocalAddrType local_addr_t, NetworkAddrType net_addr_t>
    struct address_map
    {
      protected:
        std::unordered_map<local_addr_t, net_addr_t> _local_to_remote;
        std::unordered_map<net_addr_t, local_addr_t> _remote_to_local;
        std::unordered_map<std::string, net_addr_t> _name_to_remote;

        using Lock_t = util::NullLock;
        mutable util::NullMutex addr_mutex;

      public:
        /** This functions exactly as std::unordered_map's ::insert_or_assign method. If a key equivalent
            to `local` or `remote` already exists, then they will be assigned to the corresponding value.
            Otherwise, the values will be inserted.

            The returned `bool` is true if the insertion took place and `false` if assignment occurred.
        */
        bool insert_or_assign(local_addr_t local, net_addr_t remote)
        {
            Lock_t l{addr_mutex};

            auto name = remote.name();

            auto [_1, b1] = _local_to_remote.insert_or_assign(local, remote);
            auto [_2, b2] = _remote_to_local.insert_or_assign(remote, local);
            auto [_3, b3] = _name_to_remote.insert_or_assign(name, remote);

            return b1 & b2 & b3;
        }

        std::optional<local_addr_t> get_local_from_remote(const net_addr_t& remote)
        {
            Lock_t l{addr_mutex};

            std::optional<local_addr_t> ret = std::nullopt;

            if (auto itr = _remote_to_local.find(remote); itr != _remote_to_local.end())
                ret = itr->second;

            return ret;
        }

        std::optional<net_addr_t> get_remote_from_local(const local_addr_t& local)
        {
            Lock_t l{addr_mutex};

            std::optional<net_addr_t> ret = std::nullopt;

            if (auto itr = _local_to_remote.find(local); itr != _local_to_remote.end())
                ret = itr->second;

            return ret;
        }

        std::optional<net_addr_t> get_remote_from_name(const std::string& name)
        {
            Lock_t l{addr_mutex};

            std::optional<net_addr_t> ret = std::nullopt;

            if (auto itr = _name_to_remote.find(name); itr != _local_to_remote.end())
                ret = itr->second;

            return ret;
        }

        std::optional<local_addr_t> get_local_from_name(const std::string& name)
        {
            Lock_t l{addr_mutex};

            std::optional<local_addr_t> ret = std::nullopt;

            if (auto itr = _name_to_remote.find(name); itr != _local_to_remote.end())
                ret = get_local_from_remote(itr->second);

            return ret;
        }

        bool has_local(const local_addr_t& local) const
        {
            Lock_t l{addr_mutex};

            return _local_to_remote.contains(local);
        }

        bool has_remote(const net_addr_t& remote) const
        {
            Lock_t l{addr_mutex};

            return _remote_to_local.contains(remote);
        }

        void unmap(const net_addr_t& remote)
        {
            Lock_t l{addr_mutex};

            auto name = remote.name();

            if (auto it_a = _remote_to_local.find(remote); it_a != _remote_to_local.end())
            {
                if (auto it_b = _local_to_remote.find(it_a->second); it_b != _local_to_remote.end())
                {
                    if (auto it_c = _name_to_remote.find(name); it_c != _name_to_remote.end())
                    {
                        _name_to_remote.erase(it_c);
                    }
                    _local_to_remote.erase(it_b);
                }
                _remote_to_local.erase(it_a);
            }
        }

        void unmap(const local_addr_t& local)
        {
            Lock_t l{addr_mutex};

            if (auto it_a = _local_to_remote.find(local); it_a != _local_to_remote.end())
            {
                if (auto it_b = _remote_to_local.find(it_a->second); it_b != _remote_to_local.end())
                {
                    if (auto it_c = _name_to_remote.find(it_b->first.name()); it_c != _name_to_remote.end())
                    {
                        _name_to_remote.erase(it_c);
                    }
                    _remote_to_local.erase(it_b);
                }
                _local_to_remote.erase(it_a);
            }
        }

        // All types satisfying the concept RemoteAddrType have a ::name() overload
        void unmap(const std::string& name)
        {
            Lock_t l{addr_mutex};

            if (auto it_a = _name_to_remote.find(name); it_a != _name_to_remote.end())
            {
                if (auto it_b = _remote_to_local.find(it_a->second); it_b != _remote_to_local.end())
                {
                    if (auto it_c = _local_to_remote.find(it_b->second); it_c != _local_to_remote.end())
                    {
                        _local_to_remote.erase(it_c);
                    }
                    _remote_to_local.erase(it_b);
                }
                _name_to_remote.erase(it_a);
            }
        }

        std::optional<local_addr_t> operator[](const net_addr_t& remote) { return get_local_from_remote(remote); }

        std::optional<net_addr_t> operator[](const local_addr_t& local) { return get_remote_from_local(local); }
    };
}  //  namespace llarp
