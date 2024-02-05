#pragma once
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <type_traits>

namespace llarp
{
    namespace thread
    {
        enum class ElementState : uint32_t
        {
            Empty = 0,
            Writing = 1,
            Full = 2,
            Reading = 3
        };

        enum class QueueReturn
        {
            Success,
            QueueDisabled,
            QueueEmpty,
            QueueFull
        };

        constexpr std::string_view to_string(QueueReturn val)
        {
            using namespace std::literals;
            switch (val)
            {
                case QueueReturn::Success:
                    return "Success"sv;
                case QueueReturn::QueueDisabled:
                    return "QueueDisabled"sv;
                case QueueReturn::QueueEmpty:
                    return "QueueEmpty"sv;
                case QueueReturn::QueueFull:
                    return "QueueFull"sv;
            }
            return "(queue-return-unknown)"sv;
        }

        class QueueManager
        {
            // This class provides thread-safe state management for a queue.

            // Common terminology in this class:
            // - "Combined Index": the combination of an index into the circular
            //   buffer and the generation count. Precisely:
            //
            //     Combined Index = (Generation * Capacity) + Element Index
            //
            //   The combined index has the useful property where incrementing the
            //   index when the element index is at the end of the buffer does two
            //   things:
            //     1. Sets the element index back to 0
            //     2. Increments the generation

           public:
            static constexpr size_t Alignment = 64;

            using AtomicIndex = std::atomic<std::uint32_t>;

           private:
            AtomicIndex m_pushIndex;  // Index in the buffer that the next
                                      // element will be added to.

            char m_pushPadding[Alignment - sizeof(AtomicIndex)];

            AtomicIndex m_popIndex;  // Index in the buffer that the next
                                     // element will be removed from.

            char m_popPadding[Alignment - sizeof(AtomicIndex)];

            const size_t m_capacity;  // max size of the manager.

            const uint32_t m_maxGeneration;  // Maximum generation for this object.

            const uint32_t m_maxCombinedIndex;  // Maximum combined value of index and
                                                // generation for this object.

            std::atomic<std::uint32_t>* m_states;  // Array of index states.

            AtomicIndex& pushIndex();

            AtomicIndex& popIndex();

            const AtomicIndex& pushIndex() const;

            const AtomicIndex& popIndex() const;

            // Return the next combined index
            uint32_t nextCombinedIndex(uint32_t index) const;

            // Return the next generation
            uint32_t nextGeneration(uint32_t generation) const;

           public:
            // Return the difference between the startingValue and the subtractValue
            // around a particular modulo.
            static int32_t circularDifference(uint32_t startingValue, uint32_t subtractValue, uint32_t modulo);

            // Return the number of possible generations a circular buffer can hold.
            static uint32_t numGenerations(size_t capacity);

            // The max capacity of the queue manager.
            // 2 bits are used for holding the disabled status and the number of
            // generations is at least 2.
            static constexpr size_t MAX_CAPACITY = 1 << ((sizeof(uint32_t) * 8) - 2);

            explicit QueueManager(size_t capacity);

            ~QueueManager();

            // Push operations

            // Reserve the next available index to enqueue an element at. On success:
            // - Load `index` with the next available index
            // - Load `generation` with the current generation
            //
            // If this call succeeds, other threads may spin until `commitPushIndex`
            // is called.
            QueueReturn reservePushIndex(uint32_t& generation, uint32_t& index);

            // Mark the `index` in the given `generation` as in-use. This unblocks
            // any other threads which were waiting on the index state.
            void commitPushIndex(uint32_t generation, uint32_t index);

            // Pop operations

            // Reserve the next available index to remove an element from. On success:
            // - Load `index` with the next available index
            // - Load `generation` with the current generation
            //
            // If this call succeeds, other threads may spin until `commitPopIndex`
            // is called.
            QueueReturn reservePopIndex(uint32_t& generation, uint32_t& index);

            // Mark the `index` in the given `generation` as available. This unblocks
            // any other threads which were waiting on the index state.
            void commitPopIndex(uint32_t generation, uint32_t index);

            // Disable the queue
            void disable();

            // Enable the queue
            void enable();

            // Exception safety

            // If the next available index an element can be popped from is before
            // the `endGeneration` and the `endIndex`, reserve that index into `index`
            // and `generation`.
            //
            // Return true if an index was reserved and false otherwise.
            //
            // Behaviour is undefined if `endGeneration` and `endIndex` have not been
            // acquired for writing.
            //
            // The intended usage of this method is to help remove all elements if an
            // exception is thrown between reserving and committing an index.
            // Workflow:
            // 1. call reservePopForClear
            // 2. call commitPopIndex, emptying all cells up to the reserved index
            // 3. call abortPushIndexReservation on the index.
            bool reservePopForClear(uint32_t& generation, uint32_t& index, uint32_t endGeneration, uint32_t endIndex);

            void abortPushIndexReservation(uint32_t generation, uint32_t index);

            // Accessors

            bool enabled() const;

            size_t size() const;

            size_t capacity() const;
        };
    }  // namespace thread
}  // namespace llarp
