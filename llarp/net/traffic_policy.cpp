#include "traffic_policy.hpp"

#include <llarp/util/bencode.hpp>
#include <llarp/util/str.hpp>

namespace llarp::net
{
    ProtocolInfo::ProtocolInfo(std::string_view data)
    {
        const auto parts = split(data, "/");
        protocol = ParseIPProtocol(std::string{parts[0]});
        if (parts.size() == 2)
        {
            huint16_t portHost{};
            std::string portStr{parts[1]};
            std::string protoName = IPProtocolName(protocol);
            if (const auto* serv = ::getservbyname(portStr.c_str(), protoName.c_str()))
            {
                portHost.h = serv->s_port;
            }
            else if (const auto portInt = std::stoi(portStr); portInt > 0)
            {
                portHost.h = portInt;
            }
            else
                throw std::invalid_argument{"invalid port in protocol info: " + portStr};
            port = ToNet(portHost);
        }
        else
            port = std::nullopt;
    }

    bool ProtocolInfo::MatchesPacket(const IPPacket& pkt) const
    {
        if (pkt.Header()->protocol != static_cast<std::underlying_type_t<IPProtocol>>(protocol))
            return false;

        if (not port)
            return true;
        if (const auto maybe = pkt.DstPort())
        {
            return *port == *maybe;
        }
        // we can't tell what the port is but the protocol matches and that's good enough
        return true;
    }

    bool TrafficPolicy::AllowsTraffic(const IPPacket& pkt) const
    {
        if (protocols.empty() and ranges.empty())
            return true;

        for (const auto& proto : protocols)
        {
            if (proto.MatchesPacket(pkt))
                return true;
        }
        for (const auto& range : ranges)
        {
            huint128_t dst;
            if (pkt.IsV6())
                dst = pkt.dstv6();
            else if (pkt.IsV4())
                dst = pkt.dst4to6();
            else
                return false;
            if (range.Contains(dst))
                return true;
        }
        return false;
    }

    bool ProtocolInfo::BDecode(llarp_buffer_t* buf)
    {
        port = std::nullopt;
        std::vector<uint64_t> vals;
        if (not bencode_read_list(
                [&vals](llarp_buffer_t* buf, bool more) {
                    if (more)
                    {
                        uint64_t intval;
                        if (not bencode_read_integer(buf, &intval))
                            return false;
                        vals.push_back(intval);
                    }
                    return true;
                },
                buf))
            return false;
        if (vals.empty())
            return false;
        if (vals.size() >= 1)
        {
            if (vals[0] > 255)
                return false;
            protocol = static_cast<IPProtocol>(vals[0]);
        }
        if (vals.size() >= 2)
        {
            if (vals[1] > 65536)
                return false;
            port = ToNet(huint16_t{static_cast<uint16_t>(vals[1])});
        }
        return true;
    }

    void ProtocolInfo::bt_encode(oxenc::bt_list_producer& btlp) const
    {
        try
        {
            btlp.append(static_cast<uint8_t>(protocol));
            btlp.append(ToHost(*port).h);
        }
        catch (...)
        {
            log::critical(net_cat, "Error: ProtocolInfo failed to bt encode contents!");
        }
    }

    ProtocolInfo::ProtocolInfo(std::string buf)
    {
        try
        {
            oxenc::bt_list_consumer btlc{std::move(buf)};
            protocol = static_cast<IPProtocol>(btlc.consume_integer<uint8_t>());
            port->FromString(btlc.consume_string());
        }
        catch (...)
        {
            log::critical(net_cat, "Error: ProtocolInfo failed to bt encode contents!");
        }
    }

    void TrafficPolicy::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            {
                auto sublist = btdc.consume_list_consumer();
                while (not sublist.is_finished())
                {
                    protocols.emplace(sublist.consume_string());
                }
            }
        }
        catch (...)
        {
            log::critical(net_cat, "Error: TrafficPolicy failed to populate with bt encoded contents");
        }
    }

    void TrafficPolicy::bt_encode(oxenc::bt_dict_producer& btdp) const
    {
        try
        {
            {
                auto sublist = btdp.append_list("p");
                for (auto& p : protocols)
                    p.bt_encode(sublist);
            }

            {
                auto sublist = btdp.append_list("r");
                for (auto& r : ranges)
                    r.bt_encode(sublist);
            }
        }
        catch (...)
        {
            log::critical(net_cat, "Error: TrafficPolicy failed to bt encode contents!");
        }
    }

    bool TrafficPolicy::BDecode(llarp_buffer_t* buf)
    {
        return bencode_read_dict(
            [&](llarp_buffer_t* buffer, llarp_buffer_t* key) -> bool {
                if (key == nullptr)
                    return true;
                if (key->startswith("p"))
                {
                    return BEncodeReadSet(protocols, buffer);
                }
                if (key->startswith("r"))
                {
                    return BEncodeReadSet(ranges, buffer);
                }
                return bencode_discard(buffer);
            },
            buf);
    }

    StatusObject ProtocolInfo::ExtractStatus() const
    {
        StatusObject status{
            {"protocol", static_cast<uint32_t>(protocol)},
        };
        if (port)
            status["port"] = ToHost(*port).h;
        return status;
    }

    StatusObject TrafficPolicy::ExtractStatus() const
    {
        std::vector<StatusObject> rangesStatus;
        std::transform(ranges.begin(), ranges.end(), std::back_inserter(rangesStatus), [](const auto& range) {
            return range.ToString();
        });

        std::vector<StatusObject> protosStatus;
        std::transform(protocols.begin(), protocols.end(), std::back_inserter(protosStatus), [](const auto& proto) {
            return proto.ExtractStatus();
        });

        return StatusObject{{"ranges", rangesStatus}, {"protocols", protosStatus}};
    }

}  // namespace llarp::net
