#include "tag.hpp"

namespace llarp::service
{
    SessionTag SessionTag::make_random()
    {
        SessionTag t;
        t.Randomize();
        return t;
    }

    void SessionTag::Randomize()
    {
        llarp::AlignedBuffer<16>::Randomize();
        /// ensure we are in the fc00 range
        llarp::AlignedBuffer<16>::operator[](0) = 0xfc;
    }
}  // namespace llarp::service
