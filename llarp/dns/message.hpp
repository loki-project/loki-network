#pragma once

#include "question.hpp"
#include "rr.hpp"
#include "serialize.hpp"

namespace llarp
{
    struct IPPacket;

    namespace dns
    {
        struct SRVData;

        using MsgID_t = uint16_t;
        using Fields_t = uint16_t;
        using Count_t = uint16_t;

        struct MessageHeader : public Serialize
        {
          private:
            static enum { id, fields, qd_count, an_count, ns_count, ar_count } indices;

          public:
            static constexpr size_t Size = 12;

            MessageHeader() = default;

            std::array<uint16_t, 6> _data{};

            MsgID_t _id;
            Fields_t _fields;
            Count_t _qd_count;
            Count_t _an_count;
            Count_t _ns_count;
            Count_t _ar_count;

            bool Encode(llarp_buffer_t* buf) const override;

            bool Decode(llarp_buffer_t* buf) override;

            bool decode(std::span<uint8_t> b) override;

            nlohmann::json ToJSON() const override;

            bool operator==(const MessageHeader& other) const
            {
                return _id == other._id && _fields == other._fields && _qd_count == other._qd_count
                    && _an_count == other._an_count && _ns_count == other._ns_count && _ar_count == other._ar_count;
            }
        };

        struct Message : public Serialize
        {
            explicit Message(const MessageHeader& hdr);
            explicit Message(const Question& question);

            Message(Message&& other);
            Message(const Message& other);

            nlohmann::json ToJSON() const override;

            void add_nx_reply(RR_TTL_t ttl = 1);

            void add_srv_fail(RR_TTL_t ttl = 30);

            void add_mx_reply(std::string name, uint16_t priority, RR_TTL_t ttl = 1);

            void add_CNAME_reply(std::string name, RR_TTL_t ttl = 1);

            void add_reply(std::string name, RR_TTL_t ttl = 1);

            void add_srv_reply(std::vector<SRVData> records, RR_TTL_t ttl = 1);

            void add_ns_reply(std::string name, RR_TTL_t ttl = 1);

            void add_txt_reply(std::string value, RR_TTL_t ttl = 1);

            bool Encode(llarp_buffer_t* buf) const override;

            bool Decode(llarp_buffer_t* buf) override;

            bool decode(std::span<uint8_t> /* b */) override { return {}; };  // TODO:

            // Wrapper around Encode that encodes into a new buffer and returns it
            std::vector<uint8_t> to_buffer() const;

            std::string to_string() const;

            MsgID_t hdr_id;
            Fields_t hdr_fields;
            std::vector<Question> questions;
            std::vector<ResourceRecord> answers;
            std::vector<ResourceRecord> authorities;
            std::vector<ResourceRecord> additional;
        };

        std::optional<Message> maybe_parse_dns_msg(std::string_view buf);
    }  // namespace dns

}  // namespace llarp
