#pragma once

#include "dns.hpp"
#include "name.hpp"
#include "serialize.hpp"

#include <string_view>
#include <tuple>

namespace llarp::dns
{
    inline constexpr size_t TARGET_MAX_SIZE{200};

    using SRVTuple = std::tuple<std::string, uint16_t, uint16_t, uint16_t, std::string>;

    /** SRVData

        bt-encoded keys:
            'p' : port
            's' : service protocol
            't' : target
            'u' : priority
            'w' : weight
    */
    struct SRVData
    {
        SRVData() = default;
        // SRVData constructor expecting a bt-encoded dictionary
        SRVData(oxenc::bt_dict_consumer&& btdc);
        SRVData(std::string _proto, uint16_t _priority, uint16_t _weight, uint16_t _port, std::string _target);

        /* bind-like formatted string for SRV records in config file
         *
         * format:
         *   srv=service.proto priority weight port target
         *
         * exactly one space character between parts.
         *
         * target can be empty, in which case the space after port should
         * be omitted.  if this is the case, the target is
         * interpreted as the .loki or .snode of the current context.
         *
         * if target is not empty, it must be either
         *  - simply a full stop (dot/period) OR
         *  - a name within the .loki or .snode subdomains. a target
         *    specified in this manner must not end with a full stop.
         */
        static std::optional<SRVData> from_srv_string(std::string buf);

        std::string service_proto;  // service and protocol may as well be together

        uint16_t priority;
        uint16_t weight;
        uint16_t port;

        // target string for the SRV record to point to
        // options:
        //   empty                     - refer to query name
        //   dot                       - authoritative "no such service available"
        //   any other .loki or .snode - target is that .loki or .snode
        std::string target;

        // do some basic validation on the target string
        // note: this is not a conclusive, regex solution,
        // but rather some sanity/safety checks
        bool is_valid() const;

        auto operator<=>(const SRVData& other) const
        {
            return std::tie(service_proto, priority, weight, port, target)
                <=> std::tie(other.service_proto, other.priority, other.weight, other.port, other.target);
        }

        bool operator==(const SRVData& other) const { return (*this <=> other) == 0; }

        /// so we can put SRVData in a std::set
        bool operator<(const SRVData& other) const
        {
            return std::tie(service_proto, priority, weight, port, target)
                < std::tie(other.service_proto, other.priority, other.weight, other.port, other.target);
        }

        void bt_encode(oxenc::bt_dict_producer&& btdp) const;

        // TESTNET: TODO: remove this after refactoring IntroSet -> ClientContact
        std::string bt_encode() const;

        bool bt_decode(std::string buf);

        nlohmann::json ExtractStatus() const;

      private:
        bool bt_decode(oxenc::bt_dict_consumer&& btdc);
        bool from_string(std::string_view srvString);
    };

}  // namespace llarp::dns

namespace std
{
    template <>
    struct hash<llarp::dns::SRVData>
    {
        size_t operator()(const llarp::dns::SRVData& data) const noexcept
        {
            const std::hash<std::string> h_str{};
            const std::hash<uint16_t> h_port{};
            return h_str(data.service_proto) ^ (h_str(data.target) << 3) ^ (h_port(data.priority) << 5)
                ^ (h_port(data.weight) << 7) ^ (h_port(data.port) << 9);
        }
    };
}  // namespace std
