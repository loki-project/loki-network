#pragma once

#include "name.hpp"
#include "serialize.hpp"

#include <memory>
#include <vector>

namespace llarp::dns
{
    using RRClass_t = uint16_t;
    using RRType_t = uint16_t;
    using RR_RData_t = std::vector<uint8_t>;
    using RR_TTL_t = uint32_t;

    struct ResourceRecord : public Serialize
    {
        ResourceRecord() = default;
        ResourceRecord(const ResourceRecord& other);
        ResourceRecord(ResourceRecord&& other);

        explicit ResourceRecord(std::string name, RRType_t type, RR_RData_t rdata);

        bool Encode(llarp_buffer_t* buf) const override;

        bool Decode(llarp_buffer_t* buf) override;

        bool decode(std::span<uint8_t> /* b */) override { return {}; };

        nlohmann::json ToJSON() const override;

        std::string to_string() const;

        bool HasCNameForTLD(const std::string& tld) const;

        std::string rr_name;
        RRType_t rr_type;
        RRClass_t rr_class;
        RR_TTL_t ttl;
        RR_RData_t rData;

        static constexpr bool to_string_formattable = true;
    };
}  // namespace llarp::dns
