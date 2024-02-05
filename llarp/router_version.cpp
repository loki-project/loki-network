#include "router_version.hpp"

#include <cassert>

namespace llarp
{
    RouterVersion::RouterVersion(const Version_t& router, uint64_t proto) : m_Version(router), m_ProtoVersion(proto)
    {}

    bool RouterVersion::IsCompatableWith(const RouterVersion& other) const
    {
        return m_ProtoVersion == other.m_ProtoVersion;
    }

    std::string RouterVersion::bt_encode() const
    {
        oxenc::bt_list_producer btlp;

        try
        {
            btlp.append(m_ProtoVersion);

            for (auto& v : m_Version)
                btlp.append(v);
        }
        catch (...)
        {
            log::critical(llarp_cat, "Error: RouterVersion failed to bt encode contents!");
        }

        return std::move(btlp).str();
    }

    void RouterVersion::Clear()
    {
        m_Version.fill(0);
        m_ProtoVersion = INVALID_VERSION;
        assert(IsEmpty());
    }

    bool RouterVersion::IsEmpty() const
    {
        return *this == emptyRouterVersion;
    }

    bool RouterVersion::BDecode(llarp_buffer_t* buf)
    {
        // clear before hand
        Clear();
        size_t idx = 0;
        if (not bencode_read_list(
                [this, &idx](llarp_buffer_t* buffer, bool has) {
                    if (has)
                    {
                        uint64_t i;
                        if (idx == 0)
                        {
                            uint64_t val = -1;
                            if (not bencode_read_integer(buffer, &val))
                                return false;
                            m_ProtoVersion = val;
                        }
                        else if (bencode_read_integer(buffer, &i))
                        {
                            // prevent overflow (note that idx includes version too)
                            if (idx > m_Version.max_size())
                                return false;
                            m_Version[idx - 1] = i;
                        }
                        else
                            return false;
                        ++idx;
                    }
                    return true;
                },
                buf))
            return false;
        // either full list or empty list is valid
        return idx == 4 || idx == 0;
    }

    std::string RouterVersion::to_string() const
    {
        return std::to_string(m_Version.at(0)) + "." + std::to_string(m_Version.at(1)) + "."
            + std::to_string(m_Version.at(2)) + " protocol version " + std::to_string(m_ProtoVersion);
    }

}  // namespace llarp
