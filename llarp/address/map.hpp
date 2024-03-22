#pragma once

#include "address.hpp"
#include "ip_range.hpp"
#include "types.hpp"

#include <llarp/util/formattable.hpp>

namespace llarp
{
    /** This class will accept any types satisfying the concepts LocalAddrType and RemoteAddrType
            LocalAddrType: must be inherited from Remote Address
            RemoteAddrType: oxen::quic::Address or IPRange
    */
    template <LocalAddrType local_addr_t, RemoteAddrType remote_addr_t>
    struct address_map
    {
      protected:
        std::unordered_map<local_addr_t, remote_addr_t> _local_to_remote;
        std::unordered_map<remote_addr_t, local_addr_t> _remote_to_local;
        std::unordered_map<std::string, remote_addr_t> _name_to_remote;

      public:
        std::optional<local_addr_t> get_local_from_remote(const remote_addr_t& remote)
        {
            std::optional<local_addr_t> ret = std::nullopt;

            if (auto itr = _remote_to_local.find(remote); itr != _remote_to_local.end())
                ret = itr->second;

            return ret;
        }

        std::optional<remote_addr_t> get_remote_from_local(const local_addr_t& local)
        {
            std::optional<remote_addr_t> ret = std::nullopt;

            if (auto itr = _local_to_remote.find(local); itr != _local_to_remote.end())
                ret = itr->second;

            return ret;
        }

        std::optional<remote_addr_t> get_remote_from_name(const std::string& name)
        {
            std::optional<remote_addr_t> ret = std::nullopt;

            if (auto itr = _name_to_remote.find(name); itr != _local_to_remote.end())
                ret = itr->second;

            return ret;
        }

        std::optional<local_addr_t> get_local_from_name(const std::string& name)
        {
            std::optional<local_addr_t> ret = std::nullopt;

            if (auto it_a = _name_to_remote.find(name); it_a != _local_to_remote.end())
            {
                if (auto it_b = _remote_to_local.find(it_a->second); it_a != _remote_to_local.end())
                {
                    ret = it_b->second;
                }
            }

            return ret;
        }

        void map_remote_to_local(remote_addr_t remote, local_addr_t local)
        {
            _remote_to_local.emplace(remote, local);
            _local_to_remote.emplace(local, remote);
            _name_to_remote.emplace(remote.name(), remote);
        }

        void unmap_by_remote(const remote_addr_t& remote)
        {
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

        void unmap_by_local(const local_addr_t& local)
        {
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
        void unmap_by_name(const std::string& name)
        {
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
    };
}  //  namespace llarp
