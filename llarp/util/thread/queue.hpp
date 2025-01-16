#pragma once

#include "queue_manager.hpp"
#include "threading.hpp"

#include <atomic>
#include <optional>
#include <tuple>

namespace llarp::thread
{
    template <typename Type>
    class QueuePushGuard;
    template <typename Type>
    class QueuePopGuard;

    template <typename Type>
    class Queue
    {
        // This class provides a thread-safe, lock-free, fixed-size queue.
      public:
        static constexpr size_t Alignment{64};

      private:
        Type* m_data;
        const char m_dataPadding[Alignment - sizeof(Type*)];

        QueueManager m_manager;

        std::atomic<std::uint32_t> m_waitingPoppers;
        util::Semaphore m_popSemaphore;
        const char m_popSemaphorePadding[(2u * Alignment) - sizeof(util::Semaphore)];

        std::atomic<std::uint32_t> m_waitingPushers;
        util::Semaphore m_pushSemaphore;
        const char m_pushSemaphorePadding[(2u * Alignment) - sizeof(util::Semaphore)];

        friend QueuePopGuard<Type>;
        friend QueuePushGuard<Type>;

      public:
        explicit Queue(size_t capacity);

        ~Queue();

        Queue(const Queue&) = delete;
        Queue& operator=(const Queue&) = delete;

        // Push back to the queue, blocking until space is available (if
        // required). Will fail if the queue is disabled (or becomes disabled
        // while waiting for space on the queue).
        QueueReturn pushBack(const Type& value);

        QueueReturn pushBack(Type&& value);

        // Try to push back to the queue. Return false if the queue is full or
        // disabled.
        QueueReturn tryPushBack(const Type& value);

        QueueReturn tryPushBack(Type&& value);

        // Remove an element from the queue. Block until an element is available
        Type popFront();

        // Remove an element from the queue. Block until an element is available
        // or until <timeout> microseconds have elapsed
        std::optional<Type> popFrontWithTimeout(std::chrono::microseconds timeout);

        std::optional<Type> tryPopFront();

        // Remove all elements from the queue. Note this is not atomic, and if
        // other threads `pushBack` onto the queue during this call, the `size` of
        // the queue is not guaranteed to be 0.
        void removeAll();

        // Disable the queue. All push operations will fail "fast" (including
        // blocked operations). Calling this method on a disabled queue has no
        // effect.
        void disable();

        // Enable the queue. Calling this method on a disabled queue has no
        // effect.
        void enable();

        size_t capacity() const;

        size_t size() const;

        bool enabled() const;

        bool full() const;

        bool empty() const;
    };

    // Provide a guard class to provide exception safety for pushing to a queue.
    // On destruction, unless the `release` method has been called, will remove
    // and destroy all elements from the queue, putting the queue into an empty
    // state.
    template <typename Type>
    class QueuePushGuard
    {
      private:
        Queue<Type>* m_queue;
        uint32_t m_generation;
        uint32_t m_index;

      public:
        QueuePushGuard(Queue<Type>& queue, uint32_t generation, uint32_t index)
            : m_queue(&queue), m_generation(generation), m_index(index)
        {}

        ~QueuePushGuard();

        void release();
    };

    // Provide a guard class to provide exception safety for popping from a
    // queue. On destruction, this will pop the the given element from the
    // queue.
    template <typename Type>
    class QueuePopGuard
    {
      private:
        Queue<Type>& m_queue;
        uint32_t m_generation;
        uint32_t m_index;

      public:
        QueuePopGuard(Queue<Type>& queue, uint32_t generation, uint32_t index)
            : m_queue(queue), m_generation(generation), m_index(index)
        {}

        ~QueuePopGuard();
    };

    template <typename Type>
    Queue<Type>::Queue(size_t capacity)
        : m_data(nullptr),
          m_dataPadding(),
          m_manager(capacity),
          m_waitingPoppers(0),
          m_popSemaphore(0),
          m_popSemaphorePadding(),
          m_waitingPushers(0),
          m_pushSemaphore(0),
          m_pushSemaphorePadding()
    {
        m_data = static_cast<Type*>(::operator new(capacity * sizeof(Type)));
    }

    template <typename Type>
    Queue<Type>::~Queue()
    {
        removeAll();

        // We have already deleted the queue members above, free as (void *)
        ::operator delete(static_cast<void*>(m_data));
    }

    template <typename Type>
    QueueReturn Queue<Type>::tryPushBack(const Type& value)
    {
        uint32_t generation = 0;
        uint32_t index = 0;

        // Sync point A
        //
        // The next call writes with full sequential consistency to the push
        // index, which guarantees that the relaxed read to the waiting poppers
        // count sees any waiting poppers from Sync point B.

        QueueReturn retVal = m_manager.reservePushIndex(generation, index);

        if (retVal != QueueReturn::Success)
        {
            return retVal;
        }

        // Copy into the array. If the copy constructor throws, the pushGuard will
        // roll the reserve back.

        QueuePushGuard<Type> pushGuard(*this, generation, index);

        // Construct in place.
        ::new (&m_data[index]) Type(value);

        pushGuard.release();

        m_manager.commitPushIndex(generation, index);

        if (m_waitingPoppers > 0)
        {
            m_popSemaphore.notify();
        }

        return QueueReturn::Success;
    }

    template <typename Type>
    QueueReturn Queue<Type>::tryPushBack(Type&& value)
    {
        uint32_t generation = 0;
        uint32_t index = 0;

        // Sync point A
        //
        // The next call writes with full sequential consistency to the push
        // index, which guarantees that the relaxed read to the waiting poppers
        // count sees any waiting poppers from Sync point B.

        QueueReturn retVal = m_manager.reservePushIndex(generation, index);

        if (retVal != QueueReturn::Success)
        {
            return retVal;
        }

        // Copy into the array. If the copy constructor throws, the pushGuard will
        // roll the reserve back.

        QueuePushGuard<Type> pushGuard(*this, generation, index);

        Type& dummy = value;

        // Construct in place.
        ::new (&m_data[index]) Type(std::move(dummy));

        pushGuard.release();

        m_manager.commitPushIndex(generation, index);

        if (m_waitingPoppers > 0)
        {
            m_popSemaphore.notify();
        }

        return QueueReturn::Success;
    }

    template <typename Type>
    std::optional<Type> Queue<Type>::tryPopFront()
    {
        uint32_t generation;
        uint32_t index;

        // Sync Point C.
        //
        // The call to reservePopIndex writes with full *sequential* consistency,
        // which guarantees the relaxed read to waiting poppers is synchronized
        // with Sync Point D.

        QueueReturn retVal = m_manager.reservePopIndex(generation, index);

        if (retVal != QueueReturn::Success)
        {
            return {};
        }

        // Pop guard will (even if the move/copy constructor throws)
        // - destroy the original object
        // - update the queue
        // - notify any waiting pushers

        QueuePopGuard<Type> popGuard(*this, generation, index);
        return std::optional<Type>(std::move(m_data[index]));
    }

    template <typename Type>
    QueueReturn Queue<Type>::pushBack(const Type& value)
    {
        for (;;)
        {
            QueueReturn retVal = tryPushBack(value);

            switch (retVal)
            {
                // Queue disabled.
                case QueueReturn::QueueDisabled:
                // We pushed the value back
                case QueueReturn::Success:
                    return retVal;
                default:
                    // continue on.
                    break;
            }

            m_waitingPushers.fetch_add(1, std::memory_order_relaxed);

            // Sync Point B.
            //
            // The call to `full` below loads the push index with full *sequential*
            // consistency, which gives visibility of the change above to
            // waiting pushers in Synchronisation Point B.

            if (full() && enabled())
            {
                m_pushSemaphore.wait();
            }

            m_waitingPushers.fetch_add(-1, std::memory_order_relaxed);
        }
    }

    template <typename Type>
    QueueReturn Queue<Type>::pushBack(Type&& value)
    {
        for (;;)
        {
            QueueReturn retVal = tryPushBack(std::move(value));

            switch (retVal)
            {
                // Queue disabled.
                case QueueReturn::QueueDisabled:
                // We pushed the value back
                case QueueReturn::Success:
                    return retVal;
                default:
                    // continue on.
                    break;
            }

            m_waitingPushers.fetch_add(1, std::memory_order_relaxed);

            // Sync Point B.
            //
            // The call to `full` below loads the push index with full *sequential*
            // consistency, which gives visibility of the change above to
            // waiting pushers in Synchronisation Point C.

            if (full() && enabled())
            {
                m_pushSemaphore.wait();
            }

            m_waitingPushers.fetch_add(-1, std::memory_order_relaxed);
        }
    }

    template <typename Type>
    Type Queue<Type>::popFront()
    {
        uint32_t generation = 0;
        uint32_t index = 0;
        while (m_manager.reservePopIndex(generation, index) != QueueReturn::Success)
        {
            m_waitingPoppers.fetch_add(1, std::memory_order_relaxed);

            if (empty())
            {
                m_popSemaphore.wait();
            }

            m_waitingPoppers.fetch_sub(1, std::memory_order_relaxed);
        }

        QueuePopGuard<Type> popGuard(*this, generation, index);
        return Type(std::move(m_data[index]));
    }

    template <typename Type>
    std::optional<Type> Queue<Type>::popFrontWithTimeout(std::chrono::microseconds timeout)
    {
        uint32_t generation = 0;
        uint32_t index = 0;
        bool secondTry = false;
        bool success = false;
        for (;;)
        {
            success = m_manager.reservePopIndex(generation, index) == QueueReturn::Success;

            if (secondTry || success)
                break;

            m_waitingPoppers.fetch_add(1, std::memory_order_relaxed);

            if (empty())
            {
                m_popSemaphore.waitFor(timeout);
                secondTry = true;
            }

            m_waitingPoppers.fetch_sub(1, std::memory_order_relaxed);
        }

        if (success)
        {
            QueuePopGuard<Type> popGuard(*this, generation, index);
            return Type(std::move(m_data[index]));
        }

        return {};
    }

    template <typename Type>
    void Queue<Type>::removeAll()
    {
        size_t elemCount = size();

        uint32_t poppedItems = 0;

        while (poppedItems++ < elemCount)
        {
            uint32_t generation = 0;
            uint32_t index = 0;

            if (m_manager.reservePopIndex(generation, index) != QueueReturn::Success)
            {
                break;
            }

            m_data[index].~Type();
            m_manager.commitPopIndex(generation, index);
        }

        size_t wakeups = std::min(poppedItems, m_waitingPushers.load());

        while (wakeups--)
        {
            m_pushSemaphore.notify();
        }
    }

    template <typename Type>
    void Queue<Type>::disable()
    {
        m_manager.disable();

        uint32_t numWaiting = m_waitingPushers;

        while (numWaiting--)
        {
            m_pushSemaphore.notify();
        }
    }

    template <typename Type>
    void Queue<Type>::enable()
    {
        m_manager.enable();
    }

    template <typename Type>
    size_t Queue<Type>::capacity() const
    {
        return m_manager.capacity();
    }

    template <typename Type>
    size_t Queue<Type>::size() const
    {
        return m_manager.size();
    }

    template <typename Type>
    bool Queue<Type>::enabled() const
    {
        return m_manager.enabled();
    }

    template <typename Type>
    bool Queue<Type>::full() const
    {
        return (capacity() <= size());
    }

    template <typename Type>
    bool Queue<Type>::empty() const
    {
        return (0 >= size());
    }

    template <typename Type>
    QueuePushGuard<Type>::~QueuePushGuard()
    {
        if (m_queue)
        {
            // Thread currently has the cell at index/generation. Dispose of it.

            uint32_t generation = 0;
            uint32_t index = 0;

            // We should always have at least one item to pop.
            size_t poppedItems = 1;

            while (m_queue->m_manager.reservePopForClear(generation, index, m_generation, m_index))
            {
                m_queue->m_data[index].~Type();

                poppedItems++;

                m_queue->m_manager.commitPopIndex(generation, index);
            }

            // And release

            m_queue->m_manager.abortPushIndexReservation(m_generation, m_index);

            while (poppedItems--)
            {
                m_queue->m_pushSemaphore.notify();
            }
        }
    }

    template <typename Type>
    void QueuePushGuard<Type>::release()
    {
        m_queue = nullptr;
    }

    template <typename Type>
    QueuePopGuard<Type>::~QueuePopGuard()
    {
        m_queue.m_data[m_index].~Type();
        m_queue.m_manager.commitPopIndex(m_generation, m_index);

        // Notify a pusher
        if (m_queue.m_waitingPushers > 0)
        {
            m_queue.m_pushSemaphore.notify();
        }
    }

}  // namespace llarp::thread
