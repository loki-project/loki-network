#pragma once

#include <queue>
#include <vector>

namespace llarp::util
{
    /// priority queue that uses operator > instead of operator <
    template <typename T, typename Container = std::vector<T>>
    using ascending_priority_queue = std::priority_queue<T, Container, std::greater<typename Container::value_type>>;
}  // namespace llarp::util
