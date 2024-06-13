#pragma once

#include "kademlia.hpp"
#include "key.hpp"

#include <llarp/util/logging.hpp>

#include <map>
#include <set>
#include <vector>

namespace llarp::dht
{
    static auto logcat = log::Cat("dht.bucket");

    template <typename Val_t>
    struct Bucket
    {
        using BucketStorage_t = std::map<Key_t, Val_t, XorMetric>;
        using Random_t = std::function<uint64_t()>;

        Bucket(const Key_t& us, Random_t r) : nodes(XorMetric(us)), random(std::move(r)) {}

        nlohmann::json ExtractStatus() const
        {
            nlohmann::json obj{};
            for (const auto& item : nodes)
            {
                obj[item.first.to_string()] = item.second.ExtractStatus();
            }
            return obj;
        }

        size_t size() const { return nodes.size(); }

        struct SetIntersector
        {
            bool operator()(const typename BucketStorage_t::value_type& lhs, const Key_t& rhs)
            {
                return lhs.first < rhs;
            }

            bool operator()(const Key_t& lhs, const typename BucketStorage_t::value_type& rhs)
            {
                return lhs < rhs.first;
            }
        };

        bool GetRandomNodeExcluding(Key_t& result, const std::set<Key_t>& exclude) const
        {
            std::vector<typename BucketStorage_t::value_type> candidates;
            std::set_difference(
                nodes.begin(),
                nodes.end(),
                exclude.begin(),
                exclude.end(),
                std::back_inserter(candidates),
                SetIntersector());

            if (candidates.empty())
            {
                return false;
            }
            result = candidates[random() % candidates.size()].first;
            return true;
        }

        bool FindClosest(const Key_t& target, Key_t& result) const
        {
            Key_t mindist;
            mindist.Fill(0xff);
            for (const auto& item : nodes)
            {
                auto curDist = item.first ^ target;
                if (curDist < mindist)
                {
                    mindist = curDist;
                    result = item.first;
                }
            }
            return nodes.size() > 0;
        }

        bool GetManyRandom(std::set<Key_t>& result, size_t N) const
        {
            if (nodes.size() < N || nodes.empty())
            {
                log::warning(logcat, "Not enough DHT nodes (have:{}, want:{})", nodes.size(), N);
                return false;
            }
            if (nodes.size() == N)
            {
                std::transform(nodes.begin(), nodes.end(), std::inserter(result, result.end()), [](const auto& a) {
                    return a.first;
                });

                return true;
            }
            size_t expecting = N;
            size_t sz = nodes.size();
            while (N)
            {
                auto itr = nodes.begin();
                std::advance(itr, random() % sz);
                if (result.insert(itr->first).second)
                {
                    --N;
                }
            }
            return result.size() == expecting;
        }

        bool FindCloseExcluding(const Key_t& target, Key_t& result, const std::set<Key_t>& exclude) const
        {
            Key_t maxdist;
            maxdist.Fill(0xff);
            Key_t mindist;
            mindist.Fill(0xff);
            for (const auto& item : nodes)
            {
                if (exclude.count(item.first))
                {
                    continue;
                }

                auto curDist = item.first ^ target;
                if (curDist < mindist)
                {
                    mindist = curDist;
                    result = item.first;
                }
            }
            return mindist < maxdist;
        }

        bool GetManyNearExcluding(
            const Key_t& target, std::set<Key_t>& result, size_t N, const std::set<Key_t>& exclude) const
        {
            std::set<Key_t> s(exclude.begin(), exclude.end());

            Key_t peer;
            while (N--)
            {
                if (!FindCloseExcluding(target, peer, s))
                {
                    return false;
                }
                s.insert(peer);
                result.insert(peer);
            }
            return true;
        }

        void PutNode(const Val_t& val)
        {
            auto itr = nodes.find(val.ID);
            if (itr == nodes.end() || itr->second < val)
            {
                nodes[val.ID] = val;
            }
        }

        void DelNode(const Key_t& key)
        {
            auto itr = nodes.find(key);
            if (itr != nodes.end())
            {
                nodes.erase(itr);
            }
        }

        bool HasNode(const Key_t& key) const { return nodes.find(key) != nodes.end(); }

        // remove all nodes who's key matches a predicate
        template <typename Predicate>
        void RemoveIf(Predicate pred)
        {
            auto itr = nodes.begin();
            while (itr != nodes.end())
            {
                if (pred(itr->first))
                    itr = nodes.erase(itr);
                else
                    ++itr;
            }
        }

        template <typename Visit_t>
        void ForEachNode(Visit_t visit)
        {
            for (const auto& item : nodes)
            {
                visit(item.second);
            }
        }

        void Clear() { nodes.clear(); }

        BucketStorage_t nodes;
        Random_t random;
    };
}  // namespace llarp::dht
