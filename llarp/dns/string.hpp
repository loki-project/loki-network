#pragma once

#include <string>

struct llarp_buffer_t;

namespace llarp::dns
{
    using name_t = std::string;

    /// decode name from buffer
    bool decode_name(llarp_buffer_t* buf, name_t& name);

    /// encode name to buffer
    bool encode_name(llarp_buffer_t* buf, const name_t& name);

}  // namespace llarp::dns
