#include "message.hpp"

#include "dns.hpp"
#include "srv_data.hpp"

#include <llarp/net/ip_packet.hpp>
#include <llarp/util/buffer.hpp>

#include <oxenc/endian.h>

#include <array>

namespace llarp::dns
{
    static auto logcat = log::Cat("dns");

    bool MessageHeader::Encode(llarp_buffer_t* buf) const
    {
        if (!buf->put_uint16(_id))
            return false;
        if (!buf->put_uint16(_fields))
            return false;
        if (!buf->put_uint16(_qd_count))
            return false;
        if (!buf->put_uint16(_an_count))
            return false;
        if (!buf->put_uint16(_ns_count))
            return false;
        return buf->put_uint16(_ar_count);
    }

    bool MessageHeader::Decode(llarp_buffer_t* buf)
    {
        if (!buf->read_uint16(_id))
            return false;
        if (!buf->read_uint16(_fields))
            return false;
        if (!buf->read_uint16(_qd_count))
            return false;
        if (!buf->read_uint16(_an_count))
            return false;
        if (!buf->read_uint16(_ns_count))
            return false;
        if (!buf->read_uint16(_ar_count))
            return false;
        return true;
    }

    bool MessageHeader::decode(std::span<uint8_t> b)
    {
        std::memcpy(_data.data(), b.data(), sizeof(_data));
        for (auto& d : _data)
            oxenc::big_to_host_inplace(d);
        return true;
    }

    nlohmann::json MessageHeader::ToJSON() const { return nlohmann::json{}; }

    Message::Message(Message&& other)
        : hdr_id(std::move(other.hdr_id)),
          hdr_fields(std::move(other.hdr_fields)),
          questions(std::move(other.questions)),
          answers(std::move(other.answers)),
          authorities(std::move(other.authorities)),
          additional(std::move(other.additional))
    {}

    Message::Message(const Message& other)
        : hdr_id(other.hdr_id),
          hdr_fields(other.hdr_fields),
          questions(other.questions),
          answers(other.answers),
          authorities(other.authorities),
          additional(other.additional)
    {}

    Message::Message(const MessageHeader& hdr) : hdr_id(hdr._id), hdr_fields(hdr._fields)
    {
        questions.resize(size_t(hdr._qd_count));
        answers.resize(size_t(hdr._an_count));
        authorities.resize(size_t(hdr._ns_count));
        additional.resize(size_t(hdr._ar_count));
    }

    Message::Message(const Question& question) : hdr_id{0}, hdr_fields{} { questions.emplace_back(question); }

    bool Message::Encode(llarp_buffer_t* buf) const
    {
        MessageHeader hdr;
        hdr._id = hdr_id;
        hdr._fields = hdr_fields;
        hdr._qd_count = questions.size();
        hdr._an_count = answers.size();
        hdr._ns_count = 0;
        hdr._ar_count = 0;

        if (!hdr.Encode(buf))
            return false;

        for (const auto& question : questions)
            if (!question.Encode(buf))
                return false;

        for (const auto& answer : answers)
            if (!answer.Encode(buf))
                return false;

        return true;
    }

    bool Message::Decode(llarp_buffer_t* buf)
    {
        for (auto& qd : questions)
        {
            if (!qd.Decode(buf))
            {
                log::error(logcat, "failed to decode question");
                return false;
            }
            log::debug(logcat, "question: {}", qd);
        }
        for (auto& an : answers)
        {
            if (not an.Decode(buf))
            {
                log::debug(logcat, "failed to decode answer");
                return false;
            }
        }
        return true;
    }

    nlohmann::json Message::ToJSON() const
    {
        std::vector<nlohmann::json> ques;
        std::vector<nlohmann::json> ans;
        for (const auto& q : questions)
        {
            ques.push_back(q.ToJSON());
        }
        for (const auto& a : answers)
        {
            ans.push_back(a.ToJSON());
        }
        return nlohmann::json{{"questions", ques}, {"answers", ans}};
    }

    std::vector<uint8_t> Message::to_buffer() const
    {
        std::vector<uint8_t> tmp;
        llarp_buffer_t buf{tmp};
        if (not Encode(&buf))
            throw std::runtime_error("cannot encode dns message");
        return tmp;
    }

    void Message::add_srv_fail(RR_TTL_t)
    {
        if (questions.size())
        {
            hdr_fields |= flags_RCODEServFail;
            // authorative response with recursion available
            hdr_fields |= flags_QR | flags_AA | flags_RA;
            // don't allow recursion on this request
            hdr_fields &= ~flags_RD;
        }
    }

    static constexpr uint16_t reply_flags(uint16_t setbits) { return setbits | flags_QR | flags_AA | flags_RA; }

    void Message::add_reply(std::string name, RR_TTL_t ttl)
    {
        if (questions.size())
        {
            hdr_fields = reply_flags(hdr_fields);

            const auto& question = questions[0];
            answers.emplace_back();
            auto& rec = answers.back();
            rec.rr_name = question.qname;
            rec.rr_type = question.qtype;
            rec.rr_class = qClassIN;
            rec.ttl = ttl;
            std::array<uint8_t, 512> tmp = {{0}};
            llarp_buffer_t buf(tmp);
            if (EncodeNameTo(&buf, name))
            {
                buf.sz = buf.cur - buf.base;
                rec.rData.resize(buf.sz);
                memcpy(rec.rData.data(), buf.base, buf.sz);
            }
        }
    }

    void Message::add_ns_reply(std::string name, RR_TTL_t ttl)
    {
        if (not questions.empty())
        {
            hdr_fields = reply_flags(hdr_fields);

            const auto& question = questions[0];
            answers.emplace_back();
            auto& rec = answers.back();
            rec.rr_name = question.qname;
            rec.rr_type = qTypeNS;
            rec.rr_class = qClassIN;
            rec.ttl = ttl;
            std::array<uint8_t, 512> tmp = {{0}};
            llarp_buffer_t buf(tmp);
            if (EncodeNameTo(&buf, name))
            {
                buf.sz = buf.cur - buf.base;
                rec.rData.resize(buf.sz);
                memcpy(rec.rData.data(), buf.base, buf.sz);
            }
        }
    }

    void Message::add_CNAME_reply(std::string name, RR_TTL_t ttl)
    {
        if (questions.size())
        {
            hdr_fields = reply_flags(hdr_fields);

            const auto& question = questions[0];
            answers.emplace_back();
            auto& rec = answers.back();
            rec.rr_name = question.qname;
            rec.rr_type = qTypeCNAME;
            rec.rr_class = qClassIN;
            rec.ttl = ttl;
            std::array<uint8_t, 512> tmp = {{0}};
            llarp_buffer_t buf(tmp);
            if (EncodeNameTo(&buf, name))
            {
                buf.sz = buf.cur - buf.base;
                rec.rData.resize(buf.sz);
                memcpy(rec.rData.data(), buf.base, buf.sz);
            }
        }
    }

    void Message::add_mx_reply(std::string name, uint16_t priority, RR_TTL_t ttl)
    {
        if (questions.size())
        {
            hdr_fields = reply_flags(hdr_fields);

            const auto& question = questions[0];
            answers.emplace_back();
            auto& rec = answers.back();
            rec.rr_name = question.qname;
            rec.rr_type = qTypeMX;
            rec.rr_class = qClassIN;
            rec.ttl = ttl;
            std::array<uint8_t, 512> tmp = {{0}};
            llarp_buffer_t buf(tmp);
            buf.put_uint16(priority);
            if (EncodeNameTo(&buf, name))
            {
                buf.sz = buf.cur - buf.base;
                rec.rData.resize(buf.sz);
                memcpy(rec.rData.data(), buf.base, buf.sz);
            }
        }
    }

    void Message::add_srv_reply(std::vector<SRVData> records, RR_TTL_t ttl)
    {
        hdr_fields = reply_flags(hdr_fields);

        const auto& question = questions[0];

        for (const auto& srv : records)
        {
            if (not srv.is_valid())
            {
                add_nx_reply();
                return;
            }

            answers.emplace_back();
            auto& rec = answers.back();
            rec.rr_name = question.qname;
            rec.rr_type = qTypeSRV;
            rec.rr_class = qClassIN;
            rec.ttl = ttl;

            std::array<uint8_t, 512> tmp = {{0}};
            llarp_buffer_t buf(tmp);

            buf.put_uint16(srv.priority);
            buf.put_uint16(srv.weight);
            buf.put_uint16(srv.port);

            std::string target;
            if (srv.target == "")
            {
                // get location of second dot (after service.proto) in qname
                size_t pos = question.qname.find(".");
                pos = question.qname.find(".", pos + 1);

                target = question.qname.substr(pos + 1);
            }
            else
            {
                target = srv.target;
            }

            if (not EncodeNameTo(&buf, target))
            {
                add_nx_reply();
                return;
            }

            buf.sz = buf.cur - buf.base;
            rec.rData.resize(buf.sz);
            memcpy(rec.rData.data(), buf.base, buf.sz);
        }
    }

    void Message::add_txt_reply(std::string str, RR_TTL_t ttl)
    {
        auto& rec = answers.emplace_back();
        rec.rr_name = questions[0].qname;
        rec.rr_class = qClassIN;
        rec.rr_type = qTypeTXT;
        rec.ttl = ttl;
        std::array<uint8_t, 1024> tmp{};
        llarp_buffer_t buf(tmp);
        while (not str.empty())
        {
            const auto left = std::min(str.size(), size_t{256});
            const auto sub = str.substr(0, left);
            uint8_t byte = left;
            *buf.cur = byte;
            buf.cur++;
            if (not buf.write(sub.begin(), sub.end()))
                throw std::length_error("text record too big");
            str = str.substr(left);
        }
        buf.sz = buf.cur - buf.base;
        rec.rData.resize(buf.sz);
        std::copy_n(buf.base, buf.sz, rec.rData.data());
    }

    void Message::add_nx_reply(RR_TTL_t)
    {
        if (questions.size())
        {
            answers.clear();
            authorities.clear();
            additional.clear();

            // authorative response with recursion available
            hdr_fields = reply_flags(hdr_fields);
            // don't allow recursion on this request
            hdr_fields &= ~flags_RD;
            hdr_fields |= flags_RCODENameError;
        }
    }

    std::string Message::to_string() const
    {
        return fmt::format(
            "[DNSMessage id={:x} fields={:x} questions={{{}}} answers={{{}}} authorities={{{}}} "
            "additional={{{}}}]",
            hdr_id,
            hdr_fields,
            fmt::format("{}", fmt::join(questions, ",")),
            fmt::format("{}", fmt::join(answers, ",")),
            fmt::format("{}", fmt::join(authorities, ",")),
            fmt::format("{}", fmt::join(additional, ",")));
    }

    std::optional<Message> maybe_parse_dns_msg(std::string_view b)
    {
        MessageHeader hdr{};
        llarp_buffer_t buf{b};

        if (not hdr.Decode(&buf))
            return std::nullopt;

        Message msg{hdr};
        if (not msg.Decode(&buf))
            return std::nullopt;

        return msg;
    }
}  // namespace llarp::dns
