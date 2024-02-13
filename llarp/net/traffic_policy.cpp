#include "traffic_policy.hpp"

#include <llarp/util/bencode.hpp>
#include <llarp/util/str.hpp>

namespace llarp::net
{
    static auto logcat = log::Cat("TrafficPolicy");

    // Two functions copied over from llarp/net/ip_packet_old.hpp
    std::string IPProtocolName(IPProtocol proto)
    {
        if (const auto* ent = ::getprotobynumber(static_cast<uint8_t>(proto)))
        {
            return ent->p_name;
        }

        throw std::invalid_argument{
            "cannot determine protocol name for ip proto '" + std::to_string(static_cast<int>(proto)) + "'"};
    }

    IPProtocol ParseIPProtocol(std::string data)
    {
        if (const auto* ent = ::getprotobyname(data.c_str()))
        {
            return static_cast<IPProtocol>(ent->p_proto);
        }

        if (starts_with(data, "0x"))
        {
            if (const int intVal = std::stoi(data.substr(2), nullptr, 16); intVal > 0)
                return static_cast<IPProtocol>(intVal);
        }

        throw std::invalid_argument{"no such ip protocol: '" + data + "'"};
    }

    ProtocolInfo::ProtocolInfo(std::string_view data)
    {
        const auto parts = split(data, "/");
        protocol = ParseIPProtocol(std::string{parts[0]});
        if (parts.size() == 2)
        {
            uint16_t port_host{};

            std::string portStr{parts[1]};
            std::string protoName = IPProtocolName(protocol);

            if (const auto* serv = ::getservbyname(portStr.c_str(), protoName.c_str()))
            {
                port_host = serv->s_port;
            }
            else if (const auto port_int = std::stoi(portStr); port_int > 0)
            {
                port_host = port_int;
            }
            else
                throw std::invalid_argument{"invalid port in protocol info: " + portStr};
            port = port_host;
        }
        else
            port = std::nullopt;
    }

    // DISCUSS: wtf is this
    bool ProtocolInfo::matches_packet_proto(const UDPPacket&) const
    {
        // if (pkt.Header()->protocol != static_cast<std::underlying_type_t<IPProtocol>>(protocol))
        //     return false;

        if (not port)
            return true;

        // if (const auto maybe = pkt.DstPort())
        // {
        //     return *port == *maybe;
        // }
        // we can't tell what the port is but the protocol matches and that's good enough
        return true;
    }

    bool TrafficPolicy::allow_ip_traffic(const UDPPacket& pkt) const
    {
        if (protocols.empty() and ranges.empty())
            return true;

        for (const auto& proto : protocols)
        {
            if (proto.matches_packet_proto(pkt))
                return true;
        }

        auto& dest = pkt.path.remote;
        ipv4 addrv4{oxenc::big_to_host<uint32_t>(dest.in4().sin_addr.s_addr)};
        ipv6 addrv6{dest.in6().sin6_addr.s6_addr};

        auto is_ipv4 = dest.is_ipv4();

        for (const auto& range : ranges)
        {
            if (is_ipv4)
            {
                if (range.contains(addrv4))
                    return true;
            }
            else
            {
                if (range.contains(addrv6))
                    return true;
            }
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

            port = vals[1];
        }
        return true;
    }

    void ProtocolInfo::bt_encode(oxenc::bt_list_producer& btlp) const
    {
        try
        {
            btlp.append(static_cast<uint8_t>(protocol));
            btlp.append(port);
        }
        catch (...)
        {
            log::critical(logcat, "Error: ProtocolInfo failed to bt encode contents!");
        }
    }

    ProtocolInfo::ProtocolInfo(std::string buf)
    {
        try
        {
            oxenc::bt_list_consumer btlc{std::move(buf)};
            protocol = static_cast<IPProtocol>(btlc.consume_integer<uint8_t>());
            port = btlc.consume_integer<uint16_t>();
        }
        catch (...)
        {
            log::critical(logcat, "Error: ProtocolInfo failed to bt encode contents!");
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
            log::critical(logcat, "Error: TrafficPolicy failed to populate with bt encoded contents");
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
            log::critical(logcat, "Error: TrafficPolicy failed to bt encode contents!");
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
                    // TOFIX: GFY here as well
                    // return BEncodeReadSet(protocols, buffer);
                }
                if (key->startswith("r"))
                {
                    // TOFIX: GFY here as well
                    // return BEncodeReadSet(ranges, buffer);
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
            status["port"] = *port;
        return status;
    }

    StatusObject TrafficPolicy::ExtractStatus() const
    {
        std::vector<StatusObject> rangesStatus;
        std::transform(ranges.begin(), ranges.end(), std::back_inserter(rangesStatus), [](const auto& range) {
            return range.to_string();
        });

        std::vector<StatusObject> protosStatus;
        std::transform(protocols.begin(), protocols.end(), std::back_inserter(protosStatus), [](const auto& proto) {
            return proto.ExtractStatus();
        });

        return StatusObject{{"ranges", rangesStatus}, {"protocols", protosStatus}};
    }

}  // namespace llarp::net
