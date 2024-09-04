#include "windivert.hpp"

#include "dll.hpp"
#include "handle.hpp"

#include <llarp/util/logging.hpp>
#include <llarp/util/logging/buffer.hpp>
#include <llarp/util/thread/queue.hpp>

#include <winsock2.h>

#include <windows.h>

#include <thread>
extern "C"
{
#include <windivert.h>
}

namespace
{
    using namespace oxen::log::literals;

    std::string windivert_addr_to_string(const WINDIVERT_ADDRESS& addr)
    {
        std::string layer_str{};
        std::string ifidx_str{};
        switch (addr.Layer)
        {
            case WINDIVERT_LAYER_NETWORK:
                layer_str = "WINDIVERT_LAYER_NETWORK";
                ifidx_str = "Network: [IfIdx: {}, SubIfIdx: {}]"_format(addr.Network.IfIdx, addr.Network.SubIfIdx);
                break;
            case WINDIVERT_LAYER_NETWORK_FORWARD:
                layer_str = "WINDIVERT_LAYER_NETWORK_FORWARD";
                break;
            case WINDIVERT_LAYER_FLOW:
                layer_str = "WINDIVERT_LAYER_FLOW";
                break;
            case WINDIVERT_LAYER_SOCKET:
                layer_str = "WINDIVERT_LAYER_SOCKET";
                break;
            case WINDIVERT_LAYER_REFLECT:
                layer_str = "WINDIVERT_LAYER_REFLECT";
                break;
            default:
                layer_str = "unknown";
        }

        std::string event_str{};
        switch (addr.Event)
        {
            case WINDIVERT_EVENT_NETWORK_PACKET:
                event_str = "WINDIVERT_EVENT_NETWORK_PACKET";
                break;
            case WINDIVERT_EVENT_FLOW_ESTABLISHED:
                event_str = "WINDIVERT_EVENT_FLOW_ESTABLISHED";
                break;
            case WINDIVERT_EVENT_FLOW_DELETED:
                event_str = "WINDIVERT_EVENT_FLOW_DELETED";
                break;
            case WINDIVERT_EVENT_SOCKET_BIND:
                event_str = "WINDIVERT_EVENT_SOCKET_BIND";
                break;
            case WINDIVERT_EVENT_SOCKET_CONNECT:
                event_str = "WINDIVERT_EVENT_SOCKET_CONNECT";
                break;
            case WINDIVERT_EVENT_SOCKET_LISTEN:
                event_str = "WINDIVERT_EVENT_SOCKET_LISTEN";
                break;
            case WINDIVERT_EVENT_SOCKET_ACCEPT:
                event_str = "WINDIVERT_EVENT_SOCKET_ACCEPT";
                break;
            case WINDIVERT_EVENT_SOCKET_CLOSE:
                event_str = "WINDIVERT_EVENT_SOCKET_CLOSE";
                break;
            case WINDIVERT_EVENT_REFLECT_OPEN:
                event_str = "WINDIVERT_EVENT_REFLECT_OPEN";
                break;
            case WINDIVERT_EVENT_REFLECT_CLOSE:
                event_str = "WINDIVERT_EVENT_REFLECT_CLOSE";
                break;
            default:
                event_str = "unknown";
        }

        return fmt::format(
            "Windivert WINDIVERT_ADDRESS -- Timestamp: {}, Layer: {}, Event: {}, Sniffed: {}, "
            "Outbound: {}, Loopback: {}, Imposter: {}, IPv6: {}, IPChecksum: {}, TCPChecksum: {}, "
            "UDPChecksum: {}, {}",
            addr.Timestamp,
            layer_str,
            event_str,
            addr.Sniffed ? "true" : "false",
            addr.Outbound ? "true" : "false",
            addr.Loopback ? "true" : "false",
            addr.Impostor ? "true" : "false",
            addr.IPv6 ? "true" : "false",
            addr.IPChecksum ? "true" : "false",
            addr.TCPChecksum ? "true" : "false",
            addr.UDPChecksum ? "true" : "false",
            ifidx_str);
    }
}  // namespace

namespace llarp::win32
{
    static auto logcat = log::Cat("windivert");

    namespace wd
    {
        namespace
        {
            decltype(::WinDivertOpen)* open = nullptr;
            decltype(::WinDivertClose)* close = nullptr;
            decltype(::WinDivertShutdown)* shutdown = nullptr;
            decltype(::WinDivertHelperCalcChecksums)* calc_checksum = nullptr;
            decltype(::WinDivertSend)* send = nullptr;
            decltype(::WinDivertRecv)* recv = nullptr;
            decltype(::WinDivertHelperFormatIPv4Address)* format_ip4 = nullptr;
            decltype(::WinDivertHelperFormatIPv6Address)* format_ip6 = nullptr;

            void Initialize()
            {
                if (wd::open)
                    return;

                // clang-format off
      load_dll_functions(
          "WinDivert.dll",

          "WinDivertOpen",                    open,
          "WinDivertClose",                   close,
          "WinDivertShutdown",                shutdown,
          "WinDivertHelperCalcChecksums",     calc_checksum,
          "WinDivertSend",                    send,
          "WinDivertRecv",                    recv,
          "WinDivertHelperFormatIPv4Address", format_ip4,
          "WinDivertHelperFormatIPv6Address", format_ip6);
                // clang-format on
            }
        }  // namespace

        struct Packet
        {
            std::vector<uint8_t> pkt;
            WINDIVERT_ADDRESS addr;
        };

        class IO : public llarp::vpn::PacketIO
        {
            std::function<void(void)> m_Wake;

            HANDLE m_Handle;
            std::thread m_Runner;
            std::atomic<bool> m_Shutdown{false};
            thread::Queue<Packet> m_RecvQueue;
            // dns packet queue size
            static constexpr size_t recv_queue_size = 64;

          public:
            IO(const std::string& filter_spec, std::function<void(void)> wake)
                : m_Wake{wake}, m_RecvQueue{recv_queue_size}
            {
                wd::Initialize();
                log::info(logcat, "load windivert with filterspec: '{}'", filter_spec);

                m_Handle = wd::open(filter_spec.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
                if (auto err = GetLastError())
                    throw win32::error{err, "cannot open windivert handle"};
            }

            ~IO() { wd::close(m_Handle); }

            std::optional<Packet> recv_packet() const
            {
                WINDIVERT_ADDRESS addr{};
                std::vector<uint8_t> pkt;
                pkt.resize(1500);  // net::IPPacket::MaxSize
                UINT sz{};
                if (not wd::recv(m_Handle, pkt.data(), pkt.size(), &sz, &addr))
                {
                    auto err = GetLastError();
                    if (err == ERROR_NO_DATA)
                        // The handle is shut down and the packet queue is empty
                        return std::nullopt;
                    if (err == ERROR_BROKEN_PIPE)
                    {
                        SetLastError(0);
                        return std::nullopt;
                    }

                    log::critical(logcat, "error receiving packet: {}", err);
                    throw win32::error{err, fmt::format("failed to receive packet from windivert (code={})", err)};
                }
                pkt.resize(sz);

                log::trace(logcat, "got packet of size {}B", sz);
                log::trace(logcat, "{}", windivert_addr_to_string(addr));
                return Packet{std::move(pkt), std::move(addr)};
            }

            void send_packet(Packet w_pkt) const
            {
                auto& pkt = w_pkt.pkt;
                auto* addr = &w_pkt.addr;

                addr->Outbound = !addr->Outbound;  // re-used from recv, so invert direction

                log::trace(logcat, "send dns packet of size {}B", pkt.size());
                log::trace(logcat, "{}", windivert_addr_to_string(w_pkt.addr));

                UINT sz{};
                // recalc IP packet checksum in case it needs it
                wd::calc_checksum(pkt.data(), pkt.size(), addr, 0);

                if (!wd::send(m_Handle, pkt.data(), pkt.size(), &sz, addr))
                    throw win32::error{"windivert send failed"};
            }

            virtual int PollFD() const { return -1; }

            bool write_packet(net::IPPacket) override { return false; }

            net::IPPacket read_next_packet() override
            {
                auto w_pkt = m_RecvQueue.tryPopFront();
                if (not w_pkt)
                    return net::IPPacket{};
                net::IPPacket pkt{std::move(w_pkt->pkt)};
                pkt.reply = [this, addr = std::move(w_pkt->addr)](auto pkt) {
                    if (!m_Shutdown)
                        send_packet(Packet{pkt.steal(), addr});
                };
                return pkt;
            }

            void Start() override
            {
                log::info(logcat, "starting windivert");
                if (m_Runner.joinable())
                    throw std::runtime_error{"windivert thread is already running"};

                auto read_loop = [this]() {
                    log::debug(logcat, "windivert read loop start");
                    while (true)
                    {
                        // in the read loop, read packets until they stop coming in
                        // each packet is sent off
                        if (auto maybe_pkt = recv_packet())
                        {
                            m_RecvQueue.pushBack(std::move(*maybe_pkt));
                            // wake up event loop
                            m_Wake();
                        }
                        else  // leave loop on read fail
                            break;
                    }
                    log::debug(logcat, "windivert read loop end");
                };

                m_Runner = std::thread{std::move(read_loop)};
            }

            void Stop() override
            {
                log::info(logcat, "stopping windivert");
                m_Shutdown = true;
                wd::shutdown(m_Handle, WINDIVERT_SHUTDOWN_BOTH);
                m_Runner.join();
            }
        };

    }  // namespace wd

    namespace WinDivert
    {
        std::string format_ip(uint32_t ip)
        {
            std::array<char, 128> buf;
            wd::format_ip4(ip, buf.data(), buf.size());
            return buf.data();
        }

        std::shared_ptr<llarp::vpn::PacketIO> make_interceptor(
            const std::string& filter_spec, std::function<void(void)> wake)
        {
            return std::make_shared<wd::IO>(filter_spec, wake);
        }
    }  // namespace WinDivert

}  // namespace llarp::win32
