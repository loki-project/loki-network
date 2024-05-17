#pragma once
#include <condition_variable>
#include <mutex>

namespace llarp
{
    namespace util
    {
        /// Barrier class that blocks all threads until the high water mark of
        /// threads (set during construction) is reached, then releases them all.
        class Barrier
        {
            std::mutex mutex;
            std::condition_variable cv;
            unsigned pending;

          public:
            Barrier(unsigned threads) : pending{threads} {}

            /// Returns true if *this* Block call is the one that releases all of
            /// them; returns false (i.e. after unblocking) if some other thread
            /// triggered the released.
            bool Block()
            {
                std::unique_lock lock{mutex};
                if (pending == 1)
                {
                    pending = 0;
                    lock.unlock();
                    cv.notify_all();
                    return true;
                }
                else if (pending > 1)
                {
                    pending--;
                }
                cv.wait(lock, [this] { return !pending; });
                return false;
            }
        };

    }  // namespace util
}  // namespace llarp
