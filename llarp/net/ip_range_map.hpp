#pragma once

#include "ip_range.hpp"

#include <llarp/util/types.hpp>

#include <set>
#include <vector>

namespace llarp::net
{
    /// a container that maps an ip range to a value that allows you to lookup
    /// key by range hit
    ///
    /// in the future we should do some kind of magic shit to ensure near constant time for lookups
    template <typename Value_t>
    struct IPRangeMap
    {
        using Range_t = IPRange;
        using IP_t = Range_t::Addr_t;

        using Entry_t = std::pair<Range_t, Value_t>;
        using Container_t = std::vector<Entry_t>;

        /// get a set of all values
        std::set<Value_t> Values() const
        {
            std::set<Value_t> all;
            for (const auto& entry : m_Entries)
                all.insert(entry.second);
            return all;
        }

        bool Empty() const
        {
            return m_Entries.empty();
        }

        bool ContainsValue(const Value_t& val) const
        {
            for (const auto& entry : m_Entries)
            {
                if (entry.second == val)
                    return true;
            }
            return false;
        }

        void ForEachValue(std::function<void(const Value_t&)> functor) const
        {
            for (const auto& entry : m_Entries)
                functor(entry.second);
        }

        template <typename Visit_t>
        void ForEachEntry(Visit_t visit) const
        {
            for (const auto& [range, value] : m_Entries)
                visit(range, value);
        }

        /// convert all values into type T using a transformer
        template <typename T, typename Transformer>
        std::set<T> TransformValues(Transformer transform) const
        {
            std::set<T> transformed;
            for (const auto& entry : m_Entries)
            {
                T val = transform(entry.second);
                transformed.insert(std::move(val));
            }
            return transformed;
        }

        // get a value for this exact range
        std::optional<Value_t> GetExact(Range_t range) const
        {
            for (const auto& [r, value] : m_Entries)
            {
                if (r == range)
                    return value;
            }
            return std::nullopt;
        }

        /// return a set of all entries who's range contains this IP
        std::set<Entry_t> FindAllEntries(const IP_t& addr) const
        {
            std::set<Entry_t> found;
            for (const auto& entry : m_Entries)
            {
                if (entry.first.Contains(addr))
                    found.insert(entry);
            }
            return found;
        }

        struct CompareEntry
        {
            bool operator()(const Entry_t& left, const Entry_t& right) const
            {
                return left.first < right.first;
            }
        };

        void Insert(const Range_t& addr, const Value_t& val)
        {
            m_Entries.emplace_back(addr, val);
        }

        template <typename Visit_t>
        void RemoveIf(Visit_t visit)
        {
            auto itr = m_Entries.begin();
            while (itr != m_Entries.end())
            {
                if (visit(*itr))
                    itr = m_Entries.erase(itr);
                else
                    ++itr;
            }
        }

        StatusObject ExtractStatus() const
        {
            StatusObject obj;
            for (const auto& [range, value] : m_Entries)
            {
                obj[range.to_string()] = value.to_string();
            }
            return obj;
        }

       private:
        Container_t m_Entries;
    };
}  // namespace llarp::net
