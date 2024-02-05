#pragma once

#include "constants/proto.hpp"
#include "constants/version.hpp"
#include "util/bencode.hpp"
#include "util/formattable.hpp"

#include <array>

namespace
{
    static auto llarp_cat = llarp::log::Cat("lokinet.llarp");
}  // namespace

namespace llarp
{
    struct RouterVersion
    {
        using Version_t = std::array<uint16_t, 3>;

        RouterVersion() = default;

        explicit RouterVersion(const Version_t& routerVersion, uint64_t protoVersion);

        std::string bt_encode() const;

        bool BDecode(llarp_buffer_t* buf);

        /// return true if this router version is all zeros
        bool IsEmpty() const;

        /// set to be empty
        void Clear();

        std::string to_string() const;

        /// return true if the other router version is compatible with ours
        bool IsCompatableWith(const RouterVersion& other) const;

        /// compare router versions
        bool operator<(const RouterVersion& other) const
        {
            return std::tie(m_ProtoVersion, m_Version) < std::tie(other.m_ProtoVersion, other.m_Version);
        }

        bool operator!=(const RouterVersion& other) const
        {
            return !(*this == other);
        }

        bool operator==(const RouterVersion& other) const
        {
            return m_ProtoVersion == other.m_ProtoVersion && m_Version == other.m_Version;
        }

       private:
        Version_t m_Version = {{0, 0, 0}};
        int64_t m_ProtoVersion = llarp::constants::proto_version;
    };

    template <>
    constexpr inline bool IsToStringFormattable<RouterVersion> = true;

    static constexpr int64_t INVALID_VERSION = -1;
    static const RouterVersion emptyRouterVersion({0, 0, 0}, INVALID_VERSION);

}  // namespace llarp
