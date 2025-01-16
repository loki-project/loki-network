#pragma once

#include <llarp/util/buffer.hpp>

#include <nlohmann/json.hpp>

#include <vector>

namespace llarp::dns
{
    /// base type for serializable dns entities
    struct Serialize
    {
        virtual ~Serialize() = 0;

        /// encode entity to buffer
        virtual bool Encode(llarp_buffer_t* buf) const = 0;

        /// decode entity from buffer
        virtual bool Decode(llarp_buffer_t* buf) = 0;

        virtual bool decode(std::span<uint8_t> b) = 0;

        /// convert this whatever into json
        virtual nlohmann::json ToJSON() const = 0;

        static constexpr bool to_string_formattable = true;
    };

    bool EncodeRData(llarp_buffer_t* buf, const std::vector<uint8_t>& rdata);

    bool DecodeRData(llarp_buffer_t* buf, std::vector<uint8_t>& rdata);

}  // namespace llarp::dns
