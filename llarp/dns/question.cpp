#include "question.hpp"

#include "dns.hpp"

#include <llarp/util/str.hpp>

namespace llarp::dns
{
    static auto logcat = log::Cat("dns");

    Question::Question(Question&& other)
        : qname(std::move(other.qname)), qtype(std::move(other.qtype)), qclass(std::move(other.qclass))
    {}
    Question::Question(const Question& other) : qname(other.qname), qtype(other.qtype), qclass(other.qclass) {}

    Question::Question(std::string name, QType_t type) : qname{std::move(name)}, qtype{type}, qclass{qClassIN}
    {
        if (qname.empty())
            throw std::invalid_argument{"qname cannot be empty"};
    }

    bool Question::Encode(llarp_buffer_t* buf) const
    {
        if (!EncodeNameTo(buf, qname))
            return false;
        if (!buf->put_uint16(qtype))
            return false;
        return buf->put_uint16(qclass);
    }

    bool Question::Decode(llarp_buffer_t* buf)
    {
        if (auto name = DecodeName(buf))
            qname = *std::move(name);
        else
        {
            log::error(logcat, "failed to decode name");
            return false;
        }
        if (!buf->read_uint16(qtype))
        {
            log::error(logcat, "failed to decode type");
            return false;
        }
        if (!buf->read_uint16(qclass))
        {
            log::error(logcat, "failed to decode class");
            return false;
        }
        return true;
    }

    nlohmann::json Question::ToJSON() const
    {
        return nlohmann::json{{"qname", qname}, {"qtype", qtype}, {"qclass", qclass}};
    }

    bool Question::IsName(const std::string& other) const
    {
        // does other have a . at the end?
        if (other.find_last_of('.') == (other.size() - 1))
            return other == qname;
        // no, add it and retry
        return IsName(other + ".");
    }

    bool Question::IsLocalhost() const
    {
        return (qname == "localhost.loki." or llarp::ends_with(qname, ".localhost.loki."));
    }

    bool Question::HasSubdomains() const
    {
        const auto parts = split(qname, ".", true);
        return parts.size() >= 3;
    }

    std::string Question::Subdomains() const
    {
        if (qname.size() < 2)
            return "";

        size_t pos;

        pos = qname.rfind('.', qname.size() - 2);
        if (pos == std::string::npos or pos == 0)
            return "";

        pos = qname.rfind('.', pos - 1);
        if (pos == std::string::npos or pos == 0)
            return "";

        return qname.substr(0, pos);
    }

    std::string Question::Name() const
    {
        return qname.substr(0, qname.find_last_of('.'));
    }

    bool Question::HasTLD(const std::string& tld) const
    {
        return qname.find(tld) != std::string::npos && qname.rfind(tld) == (qname.size() - tld.size()) - 1;
    }

    std::string Question::to_string() const
    {
        return fmt::format("[DNSQuestion qname={} qtype={:x} qclass={:x}]", qname, qtype, qclass);
    }
}  // namespace llarp::dns
