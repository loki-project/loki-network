#pragma once

#include <llarp/address/types.hpp>
#include <llarp/util/buffer.hpp>

#include <optional>
#include <string>

namespace llarp::dns
{
    /// decode name from buffer; return nullopt on failure
    std::optional<std::string> DecodeName(llarp_buffer_t* buf, bool trimTrailingDot = false);

    /// encode name to buffer
    bool EncodeNameTo(llarp_buffer_t* buf, std::string_view name);

    std::optional<ip_v> DecodePTR(std::string_view name);

    bool NameIsReserved(std::string_view name);

}  // namespace llarp::dns
