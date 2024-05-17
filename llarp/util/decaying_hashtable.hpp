#pragma once

#include "time.hpp"

#include <optional>
#include <unordered_map>

namespace llarp::util
{
    template <typename Key_t, typename Value_t, typename Hash_t = std::hash<Key_t>>
    struct DecayingHashTable
    {
        DecayingHashTable(std::chrono::milliseconds cacheInterval = 1h) : m_CacheInterval(cacheInterval) {}

        void Decay(std::chrono::milliseconds now)
        {
            EraseIf([&](const auto& item) { return item.second.second + m_CacheInterval <= now; });
        }

        /// return if we have this value by key
        bool Has(const Key_t& k) const { return m_Values.find(k) != m_Values.end(); }

        /// return true if inserted
        /// return false if not inserted
        bool Put(Key_t key, Value_t value, std::chrono::milliseconds now = 0s)
        {
            if (now == 0s)
                now = llarp::time_now_ms();
            return m_Values.try_emplace(std::move(key), std::make_pair(std::move(value), now)).second;
        }

        /// get value by key
        std::optional<Value_t> Get(Key_t k) const
        {
            const auto itr = m_Values.find(k);
            if (itr == m_Values.end())
                return std::nullopt;
            return itr->second.first;
        }

        /// explicit remove an item from the cache by key
        void Remove(const Key_t& key) { m_Values.erase(key); }

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
        std::unordered_map<Key_t, std::pair<Value_t, std::chrono::milliseconds>, Hash_t> m_Values;
    };
}  // namespace llarp::util
