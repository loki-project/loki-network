#pragma once

#include <llarp.hpp>
#include <llarp/rpc/rpc_client.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace omq = oxenmq;

namespace llarp::controller
{
    template <size_t N = 8>
    struct switchboard
    {
      private:
        std::bitset<N> board{};

      public:
        bool test(size_t i = 0) const { return (i < N) ? board.test(i) : false; };

        template <typename T>
            requires std::is_enum_v<T>
        bool test(T i)
        {
            return test(meta::to_underlying(i));
        }

        template <typename T>
            requires std::is_enum_v<T>
        bool set(T i)
        {
            return set(meta::to_underlying(i));
        }

        bool set(size_t i = 0)
        {
            if (i >= N)
                return false;

            if (not board.test(i))
            {
                board.set(i, true);
                return true;
            }

            return false;
        }

        bool unset(size_t i = 0)
        {
            if (i >= N)
                return false;

            if (board.test(i))
            {
                board.set(i, false);
                return true;
            }

            return false;
        }

        void clear() { board.reset(); }
    };

}  // namespace llarp::controller
