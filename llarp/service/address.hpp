#pragma once

#include <llarp/dht/key.hpp>
#include <llarp/router_id.hpp>
#include <llarp/util/aligned.hpp>

#include <functional>
#include <numeric>
#include <set>
#include <string>
#include <string_view>
#include <variant>

namespace llarp
{
    namespace service
    {
        struct Address : public AlignedBuffer<32>
        {
            /// if parsed using FromString this contains the subdomain
            /// this member is not used when comparing it's extra data for dns
            std::string subdomain;

            /// list of whitelisted gtld to permit
            static const std::set<std::string> AllowedTLDs;

            /// return true if we permit using this tld
            /// otherwise return false
            static bool PermitTLD(const char* tld);

            std::string to_string(const char* tld = ".loki") const;

            bool FromString(std::string_view str, const char* tld = ".loki");

            Address() : AlignedBuffer<32>()
            {}

            explicit Address(const std::string& str) : AlignedBuffer<32>()
            {
                if (not FromString(str))
                    throw std::runtime_error("invalid address");
            }

            explicit Address(const std::array<uint8_t, SIZE>& buf) : AlignedBuffer<32>(buf)
            {}

            Address(const Address& other) : AlignedBuffer<32>(other.as_array()), subdomain(other.subdomain)
            {}

            explicit Address(const AlignedBuffer<32>& other) : AlignedBuffer<32>(other)
            {}

            bool operator<(const Address& other) const
            {
                return as_array() < other.as_array();
            }

            bool operator==(const Address& other) const
            {
                return as_array() == other.as_array();
            }

            bool operator!=(const Address& other) const
            {
                return as_array() != other.as_array();
            }

            Address& operator=(const Address& other) = default;

            dht::Key_t ToKey() const;

            RouterID ToRouter() const
            {
                return {as_array()};
            }
        };

    }  // namespace service

    using AddressVariant_t = std::variant<service::Address, RouterID>;

    inline std::optional<AddressVariant_t> parse_address(std::string_view lokinet_addr)
    {
        RouterID router{};
        service::Address addr{};
        if (router.from_snode_address(lokinet_addr))
            return router;
        if (addr.FromString(lokinet_addr))
            return addr;
        return std::nullopt;
    }

    template <>
    inline constexpr bool IsToStringFormattable<service::Address> = true;
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::service::Address>
    {
        size_t operator()(const llarp::service::Address& addr) const
        {
            return std::accumulate(addr.begin(), addr.end(), 0, std::bit_xor{});
        }
    };
}  // namespace std
