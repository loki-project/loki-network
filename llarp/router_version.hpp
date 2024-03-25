#pragma once

#include "constants/proto.hpp"
#include "constants/version.hpp"
#include "util/formattable.hpp"

#include <array>

namespace
{}  // namespace

namespace llarp
{
    struct RouterVersion
    {
        using Version_t = std::array<uint16_t, 3>;

        RouterVersion() = default;

        explicit RouterVersion(const Version_t& routerVersion, uint64_t protoVersion);

        std::string bt_encode() const;

        bool bt_decode(std::string_view buf);

        /// return true if this router version is all zeros
        bool is_empty() const;

        /// set to be empty
        void clear();

        std::string to_string() const;

        /// return true if the other router version is compatible with ours
        bool is_compatible_with(const RouterVersion& other) const;

        /// compare router versions
        bool operator<(const RouterVersion& other) const
        {
            return std::tie(_proto, _version) < std::tie(other._proto, other._version);
        }

        bool operator!=(const RouterVersion& other) const
        {
            return !(*this == other);
        }

        bool operator==(const RouterVersion& other) const
        {
            return _proto == other._proto && _version == other._version;
        }

      private:
        Version_t _version = {{0, 0, 0}};
        int64_t _proto = llarp::constants::proto_version;
    };

    static constexpr int64_t INVALID_VERSION = -1;
    static const RouterVersion emptyRouterVersion({0, 0, 0}, INVALID_VERSION);

}  // namespace llarp
