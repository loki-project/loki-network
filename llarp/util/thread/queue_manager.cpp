#include "queue_manager.hpp"

#include <thread>

namespace llarp::thread
{
#if __cplusplus >= 201703L
    // Turn an enum into its underlying value.
    template <typename E>
    constexpr auto to_underlying(E e) noexcept
    {
        return static_cast<std::underlying_type_t<E>>(e);
    }
#else
    template <typename E>
    constexpr uint32_t to_underlying(E e) noexcept
    {
        return static_cast<uint32_t>(e);
    }
#endif
    static constexpr uint32_t GENERATION_COUNT_SHIFT = 0x2;

    // Max number of generations which can be held in an uint32_t.
    static constexpr size_t NUM_ELEMENT_GENERATIONS = 1 << ((sizeof(uint32_t) * 8) - 2);

    // mask for holding the element state from an element
    static constexpr uint32_t ELEMENT_STATE_MASK = 0x3;

    // mask for holding the disabled bit in the index.
    static constexpr uint32_t DISABLED_STATE_MASK = 1 << ((sizeof(uint32_t) * 8) - 1);

    // Max number of combinations of index and generations.
    static constexpr uint32_t NUM_COMBINED_INDEXES = DISABLED_STATE_MASK;

    bool isDisabledFlagSet(uint32_t encodedIndex) { return (encodedIndex & DISABLED_STATE_MASK); }

    uint32_t discardDisabledFlag(uint32_t encodedIndex) { return (encodedIndex & ~DISABLED_STATE_MASK); }

    uint32_t encodeElement(uint32_t generation, ElementState state)
    {
        return (generation << GENERATION_COUNT_SHIFT) | to_underlying(state);
    }

    uint32_t decodeGenerationFromElementState(uint32_t state) { return state >> GENERATION_COUNT_SHIFT; }

    ElementState decodeStateFromElementState(uint32_t state) { return ElementState(state & ELEMENT_STATE_MASK); }

    QueueManager::AtomicIndex& QueueManager::pushIndex() { return m_pushIndex; }

    QueueManager::AtomicIndex& QueueManager::popIndex() { return m_popIndex; }

    const QueueManager::AtomicIndex& QueueManager::pushIndex() const { return m_pushIndex; }

    const QueueManager::AtomicIndex& QueueManager::popIndex() const { return m_popIndex; }

    uint32_t QueueManager::nextCombinedIndex(uint32_t index) const
    {
        if (m_maxCombinedIndex == index)
        {
            return 0;
        }

        return index + 1;
    }

    uint32_t QueueManager::nextGeneration(uint32_t generation) const
    {
        if (m_maxGeneration == generation)
        {
            return 0;
        }

        return generation + 1;
    }

    size_t QueueManager::capacity() const { return m_capacity; }

    int32_t QueueManager::circularDifference(uint32_t startingValue, uint32_t subtractValue, uint32_t modulo)
    {
        assert(modulo <= (static_cast<uint32_t>(std::numeric_limits<int32_t>::max()) + 1));
        assert(startingValue < modulo);
        assert(subtractValue < modulo);

        int32_t difference = startingValue - subtractValue;
        if (difference > static_cast<int32_t>(modulo / 2))
        {
            return difference - modulo;
        }
        if (difference < -static_cast<int32_t>(modulo / 2))
        {
            return difference + modulo;
        }

        return difference;
    }

    uint32_t QueueManager::numGenerations(size_t capacity)
    {
        assert(capacity != 0);

        return static_cast<uint32_t>(std::min(NUM_COMBINED_INDEXES / capacity, NUM_ELEMENT_GENERATIONS));
    }

    QueueManager::QueueManager(size_t capacity)
        : m_pushIndex(0),
          m_popIndex(0),
          m_capacity(capacity),
          m_maxGeneration(numGenerations(capacity) - 1),
          m_maxCombinedIndex(numGenerations(capacity) * static_cast<uint32_t>(capacity) - 1)
    {
        assert(0 < capacity);
        assert(capacity <= MAX_CAPACITY);
        (void)m_pushPadding;
        (void)m_popPadding;

        m_states = new std::atomic<std::uint32_t>[capacity];

        for (size_t i = 0; i < capacity; ++i)
        {
            m_states[i] = 0;
        }
    }

    QueueManager::~QueueManager() { delete[] m_states; }

    QueueReturn QueueManager::reservePushIndex(uint32_t& generation, uint32_t& index)
    {
        uint32_t loadedPushIndex = pushIndex().load(std::memory_order_relaxed);

        uint32_t savedPushIndex = -1;

        uint32_t combinedIndex = 0;
        uint32_t currIdx = 0;
        uint32_t currGen = 0;

        // Use savedPushIndex to make us acquire an index at least twice before
        // returning QueueFull.
        // This prevents us from massive contention when we have a queue of size 1

        for (;;)
        {
            if (isDisabledFlagSet(loadedPushIndex))
            {
                return QueueReturn::QueueDisabled;
            }

            combinedIndex = discardDisabledFlag(loadedPushIndex);

            currGen = static_cast<uint32_t>(combinedIndex / m_capacity);
            currIdx = static_cast<uint32_t>(combinedIndex % m_capacity);

            uint32_t compare = encodeElement(currGen, ElementState::Empty);
            const uint32_t swap = encodeElement(currGen, ElementState::Writing);

            if (m_states[currIdx].compare_exchange_strong(compare, swap))
            {
                // We changed the state.
                generation = currGen;
                index = currIdx;
                break;
            }

            // We failed to reserve the index. Use the result from cmp n swap to
            // determine if the queue was full or not. Either:
            // 1. The cell is from a previous generation (so the queue is full)
            // 2. Another cell has reserved this cell for writing, but not commited
            // yet
            // 3. The push index has been changed between the load and the cmp.

            uint32_t elemGen = decodeGenerationFromElementState(compare);

            auto difference = static_cast<int32_t>(currGen - elemGen);

            if (difference == 1 || (difference == -static_cast<int32_t>(m_maxGeneration)))
            {
                // Queue is full.

                assert(1 == circularDifference(currGen, elemGen, m_maxGeneration + 1));

                ElementState state = decodeStateFromElementState(compare);

                if (state == ElementState::Reading)
                {
                    // Another thread is reading. Yield this thread
                    std::this_thread::yield();
                    loadedPushIndex = pushIndex().load(std::memory_order_relaxed);
                    continue;
                }

                assert(state != ElementState::Empty);

                if (savedPushIndex != loadedPushIndex)
                {
                    // Make another attempt to check the queue is full before failing
                    std::this_thread::yield();
                    savedPushIndex = loadedPushIndex;
                    loadedPushIndex = pushIndex().load(std::memory_order_relaxed);
                    continue;
                }

                return QueueReturn::QueueFull;
            }

            // Another thread has already acquired this cell, try to increment the
            // push index and go again.

            assert(0 >= circularDifference(currGen, elemGen, m_maxGeneration + 1));

            const uint32_t next = nextCombinedIndex(combinedIndex);
            pushIndex().compare_exchange_strong(combinedIndex, next);
            loadedPushIndex = combinedIndex;
        }

        // We got the cell, increment the push index
        const uint32_t next = nextCombinedIndex(combinedIndex);
        pushIndex().compare_exchange_strong(combinedIndex, next);

        return QueueReturn::Success;
    }

    void QueueManager::commitPushIndex(uint32_t generation, uint32_t index)
    {
        assert(generation <= m_maxGeneration);
        assert(index < m_capacity);
        assert(ElementState::Writing == decodeStateFromElementState(m_states[index]));
        assert(generation == decodeGenerationFromElementState(m_states[index]));

        m_states[index] = encodeElement(generation, ElementState::Full);
    }

    QueueReturn QueueManager::reservePopIndex(uint32_t& generation, uint32_t& index)
    {
        uint32_t loadedPopIndex = popIndex().load();
        uint32_t savedPopIndex = -1;

        uint32_t currIdx = 0;
        uint32_t currGen = 0;

        for (;;)
        {
            currGen = static_cast<uint32_t>(loadedPopIndex / m_capacity);
            currIdx = static_cast<uint32_t>(loadedPopIndex % m_capacity);

            // Try to swap this state from full to reading.

            uint32_t compare = encodeElement(currGen, ElementState::Full);
            const uint32_t swap = encodeElement(currGen, ElementState::Reading);

            if (m_states[currIdx].compare_exchange_strong(compare, swap))
            {
                generation = currGen;
                index = currIdx;
                break;
            }

            // We failed to reserve the index. Use the result from cmp n swap to
            // determine if the queue was full or not. Either:
            // 1. The cell is from a previous generation (so the queue is empty)
            // 2. The cell is from the current generation and empty (so the queue is
            // empty)
            // 3. The queue is being written to
            // 4. The pop index has been changed between the load and the cmp.

            uint32_t elemGen = decodeGenerationFromElementState(compare);
            ElementState state = decodeStateFromElementState(compare);

            auto difference = static_cast<int32_t>(currGen - elemGen);

            if (difference == 1 || (difference == -static_cast<int32_t>(m_maxGeneration)))
            {
                // Queue is full.
                assert(state == ElementState::Reading);
                assert(1 == (circularDifference(currGen, elemGen, m_maxGeneration + 1)));

                return QueueReturn::QueueEmpty;
            }

            if (difference == 0 && state == ElementState::Empty)
            {
                // The cell is empty in the current generation, so the queue is empty

                if (savedPopIndex != loadedPopIndex)
                {
                    std::this_thread::yield();
                    savedPopIndex = loadedPopIndex;
                    loadedPopIndex = popIndex().load(std::memory_order_relaxed);
                    continue;
                }

                return QueueReturn::QueueEmpty;
            }

            if (difference != 0 || state == ElementState::Writing)
            {
                // The cell is currently being written to or the index is outdated)
                // Yield and try again.
                std::this_thread::yield();
                loadedPopIndex = popIndex().load(std::memory_order_relaxed);
                continue;
            }

            popIndex().compare_exchange_strong(loadedPopIndex, nextCombinedIndex(loadedPopIndex));
        }

        popIndex().compare_exchange_strong(loadedPopIndex, nextCombinedIndex(loadedPopIndex));

        return QueueReturn::Success;
    }

    void QueueManager::commitPopIndex(uint32_t generation, uint32_t index)
    {
        assert(generation <= m_maxGeneration);
        assert(index < m_capacity);
        assert(decodeStateFromElementState(m_states[index]) == ElementState::Reading);
        assert(generation == decodeGenerationFromElementState(m_states[index]));

        m_states[index] = encodeElement(nextGeneration(generation), ElementState::Empty);
    }

    void QueueManager::disable()
    {
        // Loop until we set the disabled bit
        for (;;)
        {
            uint32_t index = pushIndex();

            if (isDisabledFlagSet(index))
            {
                // Queue is already disabled(?!)
                return;
            }

            if (pushIndex().compare_exchange_strong(index, index | DISABLED_STATE_MASK))
            {
                // queue has been disabled
                return;
            }
        }
    }

    void QueueManager::enable()
    {
        for (;;)
        {
            uint32_t index = pushIndex();

            if (!isDisabledFlagSet(index))
            {
                // queue is already enabled.
                return;
            }

            if (pushIndex().compare_exchange_strong(index, index & ~DISABLED_STATE_MASK))
            {
                // queue has been enabled
                return;
            }
        }
    }

    bool QueueManager::reservePopForClear(
        uint32_t& generation, uint32_t& index, uint32_t endGeneration, uint32_t endIndex)
    {
        assert(endGeneration <= m_maxGeneration);
        assert(endIndex < m_capacity);

        uint32_t loadedCombinedIndex = popIndex().load(std::memory_order_relaxed);

        for (;;)
        {
            uint32_t endCombinedIndex = (endGeneration * static_cast<uint32_t>(m_capacity)) + endIndex;

            if (circularDifference(endCombinedIndex, loadedCombinedIndex, m_maxCombinedIndex + 1) == 0)
            {
                return false;
            }

            assert(0 < circularDifference(endCombinedIndex, loadedCombinedIndex, m_maxCombinedIndex + 1));

            auto currIdx = static_cast<uint32_t>(loadedCombinedIndex % m_capacity);
            auto currGen = static_cast<uint32_t>(loadedCombinedIndex / m_capacity);

            // Try to swap this cell from Full to Reading.
            // We only set this to Empty after trying to increment popIndex, so we
            // don't race against another thread.

            uint32_t compare = encodeElement(currGen, ElementState::Full);
            const uint32_t swap = encodeElement(currGen, ElementState::Reading);

            if (m_states[currIdx].compare_exchange_strong(compare, swap))
            {
                // We've dropped this index.

                generation = currGen;
                index = currIdx;
                break;
            }

            ElementState state = decodeStateFromElementState(compare);

            if (state == ElementState::Writing || state == ElementState::Full)
            {
                // Another thread is writing to this cell, or this thread has slept
                // for too long.
                std::this_thread::yield();
                loadedCombinedIndex = popIndex().load(std::memory_order_relaxed);
                continue;
            }

            const uint32_t next = nextCombinedIndex(loadedCombinedIndex);
            popIndex().compare_exchange_strong(loadedCombinedIndex, next);
        }

        // Attempt to increment the index.
        const uint32_t next = nextCombinedIndex(loadedCombinedIndex);
        popIndex().compare_exchange_strong(loadedCombinedIndex, next);

        return true;
    }

    void QueueManager::abortPushIndexReservation(uint32_t generation, uint32_t index)
    {
        assert(generation <= m_maxGeneration);
        assert(index < m_capacity);
        assert(static_cast<uint32_t>((generation * m_capacity) + index) == popIndex().load(std::memory_order_relaxed));
        assert(decodeStateFromElementState(m_states[index]) == ElementState::Writing);
        assert(generation == decodeGenerationFromElementState(m_states[index]));

        uint32_t loadedPopIndex = popIndex().load(std::memory_order_relaxed);

        assert(generation == loadedPopIndex / m_capacity);
        assert(index == loadedPopIndex % m_capacity);

        m_states[index] = encodeElement(generation, ElementState::Reading);

        const uint32_t nextIndex = nextCombinedIndex(loadedPopIndex);
        popIndex().compare_exchange_strong(loadedPopIndex, nextIndex);

        m_states[index] = encodeElement(nextGeneration(generation), ElementState::Empty);
    }

    size_t QueueManager::size() const
    {
        // Note that we rely on these loads being sequentially consistent.

        uint32_t combinedPushIndex = discardDisabledFlag(pushIndex());
        uint32_t combinedPopIndex = popIndex();

        int32_t difference = combinedPushIndex - combinedPopIndex;

        if (difference >= 0)
        {
            if (difference > static_cast<int32_t>(m_capacity))
            {
                // We've raced between getting push and pop indexes, in this case, it
                // means the queue is empty.
                assert(0 > circularDifference(combinedPushIndex, combinedPopIndex, m_maxCombinedIndex + 1));

                return 0;
            }

            return static_cast<size_t>(difference);
        }

        if (difference < -static_cast<int32_t>(m_maxCombinedIndex / 2))
        {
            assert(0 < circularDifference(combinedPushIndex, combinedPopIndex, m_maxCombinedIndex + 1));

            difference += m_maxCombinedIndex + 1;
            return std::min(static_cast<size_t>(difference), m_capacity);
        }

        return 0;
    }

    bool QueueManager::enabled() const { return !isDisabledFlagSet(pushIndex().load()); }
}  // namespace llarp::thread
