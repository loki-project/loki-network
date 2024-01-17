#pragma once

#include "dns.hpp"
#include "name.hpp"
#include "serialize.hpp"

#include <llarp/util/types.hpp>

#include <string_view>
#include <tuple>

namespace llarp::dns
{
    using SRVTuple = std::tuple<std::string, uint16_t, uint16_t, uint16_t, std::string>;

    struct SRVData
    {
        static constexpr size_t TARGET_MAX_SIZE = 200;

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
        bool IsValid() const;

        SRVTuple toTuple() const;

        auto toTupleRef() const
        {
            return std::tie(service_proto, priority, weight, port, target);
        }

        /// so we can put SRVData in a std::set
        bool operator<(const SRVData& other) const
        {
            return toTupleRef() < other.toTupleRef();
        }

        bool operator==(const SRVData& other) const
        {
            return toTupleRef() == other.toTupleRef();
        }

        std::string bt_encode() const;

        bool BDecode(llarp_buffer_t*);

        StatusObject ExtractStatus() const;

        static SRVData fromTuple(SRVTuple tuple);

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
        bool fromString(std::string_view srvString);
    };

}  // namespace llarp::dns

namespace std
{
    template <>
    struct hash<llarp::dns::SRVData>
    {
        size_t operator()(const llarp::dns::SRVData& data) const
        {
            const std::hash<std::string> h_str{};
            const std::hash<uint16_t> h_port{};
            return h_str(data.service_proto) ^ (h_str(data.target) << 3) ^ (h_port(data.priority) << 5)
                ^ (h_port(data.weight) << 7) ^ (h_port(data.port) << 9);
        }
    };
}  // namespace std
