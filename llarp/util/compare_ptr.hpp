#pragma once
#include <functional>
#include <memory>

namespace llarp
{
    /// type for comparing smart pointer's managed values
    template <typename Ptr_t, typename Compare = std::less<>>
    struct ComparePtr
    {
        bool operator()(const Ptr_t& left, const Ptr_t& right) const
        {
            if (left && right)
                return Compare()(*left, *right);

            return Compare()(left, right);
        }
    };

    /// type for comparing weak_ptr by value
    template <typename Type_t, typename Compare = std::less<>>
    struct CompareWeakPtr
    {
        bool operator()(const std::weak_ptr<Type_t>& left, const std::weak_ptr<Type_t>& right) const
        {
            return ComparePtr<std::shared_ptr<Type_t>, Compare>{}(left.lock(), right.lock());
        }
    };

}  // namespace llarp
