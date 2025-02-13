#include "policy.hpp"

#include "ip_packet.hpp"

#include <llarp/util/logging.hpp>
#include <llarp/util/str.hpp>

namespace llarp
{
    static constexpr auto HOST_STANDARD = "host/standard/ipv4"sv;
    static constexpr auto HOST_TUNNEL = "host/tunnel/ipv4"sv;
    static constexpr auto EXIT_STANDARD = "exit/standard/ipv4"sv;
    static constexpr auto EXIT_TUNNEL = "exit/tunnel/ipv4"sv;

    std::string protoflag_string(uint8_t p)
    {
        std::string_view root;

        if (p & meta::to_underlying(protocol_flag::EXIT))
            root = (p & meta::to_underlying(protocol_flag::QUICTUN)) ? EXIT_TUNNEL : EXIT_STANDARD;
        else
            root = (p & meta::to_underlying(protocol_flag::QUICTUN)) ? HOST_TUNNEL : HOST_STANDARD;

        return "<{}{}>"_format(root, p & meta::to_underlying(protocol_flag::IPV6) ? "/ipv6" : "");
    }

    namespace net
    {
        static auto logcat = log::Cat("TrafficPolicy");

        // Two functions copied over from llarp/net/ip_packet_old.hpp
        static std::string ip_proto_str(IPProtocol proto)
        {
            if (const auto* ent = ::getprotobynumber(meta::to_underlying(proto)))
            {
                return ent->p_name;
            }

            throw std::invalid_argument{"Cannot determine protocol name for IP Protocol: {}"_format(proto)};
        }

        static IPProtocol parse_ip_proto(std::string data)
        {
            if (const auto* ent = ::getprotobyname(data.c_str()))
            {
                return static_cast<IPProtocol>(ent->p_proto);
            }

            if (data.starts_with("0x"))
            {
                if (const int intVal = std::stoi(data.substr(2), nullptr, 16); intVal > 0)
                    return static_cast<IPProtocol>(intVal);
            }

            throw std::invalid_argument{"Call to ::getprotobyname failed for input: {}"_format(data)};
        }

        bool ProtocolInfo::matches_packet_proto(const IPPacket& pkt) const { return pkt.protocol() == proto; }

        bool ExitPolicy::allow_ip_traffic(const IPPacket& pkt) const
        {
            log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

            if (protocols.empty() and ranges.empty())
                return true;

            for (const auto& proto : protocols)
            {
                if (proto.matches_packet_proto(pkt))
                    return true;
            }

            auto is_ipv4 = pkt.is_ipv4();
            ip_v pkt_ip;

            if (is_ipv4)
                pkt_ip = pkt.dest_ipv4();
            else
                pkt_ip = pkt.dest_ipv6();

            for (const auto& range : ranges)
            {
                if (range.contains(pkt_ip))
                    return true;
            }

            return false;
        }

        void ProtocolInfo::bt_decode(oxenc::bt_list_consumer& btlc)
        {
            try
            {
                proto = IPProtocol{btlc.consume_integer<uint8_t>()};

                if (not btlc.is_finished())
                    port = btlc.consume_integer<uint16_t>();
            }
            catch (...)
            {
                log::critical(logcat, "ProtocolInfo parsing exception");
                throw;
            }
        }

        bool ProtocolInfo::bt_decode(std::string_view buf)
        {
            port = std::nullopt;

            try
            {
                oxenc::bt_list_consumer btlc{buf};

                bt_decode(btlc);
            }
            catch (const std::exception& e)
            {
                // DISCUSS: rethrow or print warning/return false...?
                auto err = "ProtocolInfo parsing exception: {}"_format(e.what());
                log::warning(logcat, "{}", err);
                throw std::runtime_error{err};
            }

            return true;
        }

        void ProtocolInfo::bt_encode(oxenc::bt_list_producer& btlp) const
        {
            try
            {
                btlp.append(meta::to_underlying(proto));

                if (port.has_value())
                    btlp.append(*port);
            }
            catch (...)
            {
                log::critical(logcat, "Error: ProtocolInfo failed to bt encode contents!");
            }
        }

        ProtocolInfo::ProtocolInfo(std::string_view buf)
        {
            try
            {
                oxenc::bt_list_consumer btlc{buf};
                proto = IPProtocol{btlc.consume_integer<uint8_t>()};

                if (not btlc.is_finished())
                    port = btlc.consume_integer<uint16_t>();
            }
            catch (...)
            {
                log::critical(logcat, "Error: ProtocolInfo failed to bt encode contents!");
            }
        }

        void ExitPolicy::bt_decode(oxenc::bt_dict_consumer&& btdc)
        {
            try
            {
                {
                    auto [key, sublist] = btdc.next_list_consumer();

                    if (key != "p")
                        throw std::invalid_argument{"Unexpected key (expected:'p', actual:'{}')"_format(key)};

                    while (not sublist.is_finished())
                    {
                        protocols.emplace(sublist.consume_string_view());
                    }
                }

                {
                    auto [key, sublist] = btdc.next_list_consumer();

                    if (key != "r")
                        throw std::invalid_argument{"Unexpected key (expected:'r', actual:'{}')"_format(key)};

                    while (not sublist.is_finished())
                    {
                        ranges.emplace(sublist.consume_string());
                    }
                }
            }
            catch (...)
            {
                log::critical(logcat, "Error: TrafficPolicy failed to populate with bt encoded contents");
                throw;
            }
        }

        void ExitPolicy::bt_encode(oxenc::bt_dict_producer&& btdp) const
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

        bool ExitPolicy::bt_decode(std::string_view buf)
        {
            try
            {
                bt_decode(oxenc::bt_dict_consumer{buf});
            }
            catch (const std::exception& e)
            {
                // DISCUSS: rethrow or print warning/return false...?
                auto err = "TrafficPolicy parsing exception: {}"_format(e.what());
                log::warning(logcat, "{}", err);
                throw std::runtime_error{err};
            }

            return true;
        }
    }  // namespace net
}  // namespace llarp
