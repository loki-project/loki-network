#pragma once

#include "time.hpp"

#include <unordered_map>

namespace llarp::util
{
    template <typename Val_t, typename Hash_t = std::hash<Val_t>>
    struct DecayingHashSet
    {
        DecayingHashSet(std::chrono::milliseconds cacheInterval = 1s) : m_CacheInterval(cacheInterval) {}

        size_t Size() const { return m_Values.size(); }

        /// determine if we have v contained in our decaying hashset
        bool Contains(const Val_t& v) const { return m_Values.count(v) != 0; }

        /// return true if inserted
        /// return false if not inserted
        bool Insert(const Val_t& v, std::chrono::milliseconds now = 0s)
        {
            if (now == 0s)
                now = llarp::time_now_ms();
            return m_Values.try_emplace(v, now).second;
        }

        /// upsert will insert or update a value with time as now
        void Upsert(const Val_t& v) { m_Values[v] = llarp::time_now_ms(); }

        /// decay hashset entries
        void Decay(std::chrono::milliseconds now = 0s)
        {
            if (now == 0s)
                now = llarp::time_now_ms();
            EraseIf([&](const auto& item) { return (m_CacheInterval + item.second) <= now; });
        }

        std::chrono::milliseconds DecayInterval() const { return m_CacheInterval; }

        bool Empty() const { return m_Values.empty(); }

        void DecayInterval(std::chrono::milliseconds interval) { m_CacheInterval = interval; }

        void Remove(const Val_t& val) { m_Values.erase(val); }

      private:
        template <typename Predicate_t>
        void EraseIf(Predicate_t pred)
        {
            for (auto i = m_Values.begin(), last = m_Values.end(); i != last;)
            {
                if (pred(*i))
                {
                    i = m_Values.erase(i);
                }
                else
                {
                    ++i;
                }
            }
        }

        std::chrono::milliseconds m_CacheInterval;
        std::unordered_map<Val_t, std::chrono::milliseconds, Hash_t> m_Values;
    };
}  // namespace llarp::util
