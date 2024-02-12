#pragma once

#include "question.hpp"
#include "rr.hpp"
#include "serialize.hpp"

namespace llarp
{
    namespace dns
    {
        struct SRVData;

        using MsgID_t = uint16_t;
        using Fields_t = uint16_t;
        using Count_t = uint16_t;

        struct MessageHeader : public Serialize
        {
            static constexpr size_t Size = 12;

            MessageHeader() = default;

            MsgID_t id;
            Fields_t fields;
            Count_t qd_count;
            Count_t an_count;
            Count_t ns_count;
            Count_t ar_count;

            bool Encode(llarp_buffer_t* buf) const override;

            bool Decode(llarp_buffer_t* buf) override;

            StatusObject ToJSON() const override;

            bool operator==(const MessageHeader& other) const
            {
                return id == other.id && fields == other.fields && qd_count == other.qd_count
                    && an_count == other.an_count && ns_count == other.ns_count && ar_count == other.ar_count;
            }
        };

        struct Message : public Serialize
        {
            explicit Message(const MessageHeader& hdr);
            explicit Message(const Question& question);

            Message(Message&& other);
            Message(const Message& other);

            StatusObject ToJSON() const override;

            void add_nx_reply(RR_TTL_t ttl = 1);

            void add_srv_fail(RR_TTL_t ttl = 30);

            void add_mx_reply(std::string name, uint16_t priority, RR_TTL_t ttl = 1);

            void add_CNAME_reply(std::string name, RR_TTL_t ttl = 1);

            void add_IN_reply(llarp::huint128_t addr, bool isV6, RR_TTL_t ttl = 1);

            void add_reply(std::string name, RR_TTL_t ttl = 1);

            void add_srv_reply(std::vector<SRVData> records, RR_TTL_t ttl = 1);

            void add_ns_reply(std::string name, RR_TTL_t ttl = 1);

            void add_txt_reply(std::string value, RR_TTL_t ttl = 1);

            bool Encode(llarp_buffer_t* buf) const override;

            bool Decode(llarp_buffer_t* buf) override;

            // Wrapper around Encode that encodes into a new buffer and returns it
            [[nodiscard]] OwnedBuffer to_buffer() const;

            std::string to_string() const;

            MsgID_t hdr_id;
            Fields_t hdr_fields;
            std::vector<Question> questions;
            std::vector<ResourceRecord> answers;
            std::vector<ResourceRecord> authorities;
            std::vector<ResourceRecord> additional;
        };

        std::optional<Message> maybe_parse_dns_msg(llarp_buffer_t buf);
    }  // namespace dns

    template <>
    constexpr inline bool IsToStringFormattable<llarp::dns::Message> = true;
}  // namespace llarp
