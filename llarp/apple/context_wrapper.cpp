#include "context_wrapper.h"

#include "context.hpp"
#include "vpn_interface.hpp"

#include <llarp/address/ip_packet.hpp>
#include <llarp/config/config.hpp>
#include <llarp/constants/apple.hpp>
#include <llarp/ev/libuv.hpp>
#include <llarp/util/fs.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/logging/buffer.hpp>
#include <llarp/util/logging/callback_sink.hpp>

// #include <uvw/loop.h>

#include <cassert>
#include <cstdint>
#include <cstring>

namespace
{
    struct instance_data
    {
        llarp::apple::Context context;
        std::thread runner;
        packet_writer_callback packet_writer;
        start_reading_callback start_reading;

        std::weak_ptr<llarp::apple::VPNInterface> iface;
    };

}  // namespace

// Expose this with C linkage so that objective-c can use it
extern "C" const uint16_t dns_trampoline_port = llarp::apple::dns_trampoline_port;

void* llarp_apple_init(llarp_apple_config* appleconf)
{
    llarp::log::clear_sinks();
    llarp::log::add_sink(std::make_shared<llarp::logging::CallbackSink_mt>(
        [](const char* msg, void* nslog) { reinterpret_cast<ns_logger_callback>(nslog)(msg); },
        nullptr,
        reinterpret_cast<void*>(appleconf->ns_logger)));
    llarp::logRingBuffer = std::make_shared<llarp::log::RingBufferSink>(100);
    llarp::log::add_sink(llarp::logRingBuffer, llarp::log::DEFAULT_PATTERN_MONO);

    try
    {
        auto config_dir = fs::u8path(appleconf->config_dir);
        auto config = std::make_shared<llarp::Config>(config_dir);
        fs::path config_path = config_dir / "lokinet.ini";
        if (!fs::exists(config_path))
            llarp::ensure_config(config_dir, config_path, /*overwrite=*/false, /*asRouter=*/false);
        config->load(config_path);

        // If no range is specified then go look for a free one, set that in the config, and then
        // return it to the caller via the char* parameters.
        auto& range = config->network.if_addr;
        if (!range.addr.h)
        {
            if (auto maybe = llarp::net::Platform::Default_ptr()->find_free_range())
                range = *maybe;
            else
                throw std::runtime_error{"Could not find any free IP range"};
        }
        auto addr = llarp::net::TruncateV6(range.addr).to_string();
        auto mask = llarp::net::TruncateV6(range.netmask_bits).to_string();
        if (addr.size() > 15 || mask.size() > 15)
            throw std::runtime_error{"Unexpected non-IPv4 tunnel range configured"};
        std::strncpy(appleconf->tunnel_ipv4_ip, addr.c_str(), sizeof(appleconf->tunnel_ipv4_ip));
        std::strncpy(appleconf->tunnel_ipv4_netmask, mask.c_str(), sizeof(appleconf->tunnel_ipv4_netmask));

        // TODO: in the future we want to do this properly with our pubkey (see issue #1705), but
        // that's going to take a bit more work because we currently can't *get* the (usually)
        // ephemeral pubkey at this stage of lokinet configuration.  So for now we just stick our
        // IPv4 address into it until #1705 gets implemented.
        llarp::huint128_t ipv6{llarp::uint128_t{0xfd2e'6c6f'6b69'0000, llarp::net::TruncateV6(range.addr).h}};
        std::strncpy(appleconf->tunnel_ipv6_ip, ipv6.to_string().c_str(), sizeof(appleconf->tunnel_ipv6_ip));
        appleconf->tunnel_ipv6_prefix = 48;

        appleconf->upstream_dns[0] = '\0';
        for (auto& upstream : config->dns.upstream_dns)
        {
            if (upstream.isIPv4())
            {
                std::strcpy(appleconf->upstream_dns, upstream.hostString().c_str());
                appleconf->upstream_dns_port = upstream.getPort();
                break;
            }
        }

#ifdef MACOS_SYSTEM_EXTENSION
        std::strncpy(
            appleconf->dns_bind_ip, config->dns.m_bind.front().hostString().c_str(), sizeof(appleconf->dns_bind_ip));
#endif

        // If no explicit bootstrap then set the system default one included with the app bundle
        if (config->bootstrap.files.empty())
            config->bootstrap.files.push_back(fs::u8path(appleconf->default_bootstrap));

        auto inst = std::make_unique<instance_data>();
        inst->context.Configure(std::move(config));
        inst->context.route_callbacks = appleconf->route_callbacks;

        inst->packet_writer = appleconf->packet_writer;
        inst->start_reading = appleconf->start_reading;

        return inst.release();
    }
    catch (const std::exception& e)
    {
        llarp::LogError("Failed to initialize lokinet from config: ", e.what());
    }
    return nullptr;
}

int llarp_apple_start(void* lokinet, void* callback_context)
{
    auto* inst = static_cast<instance_data*>(lokinet);

    inst->context.callback_context = callback_context;

    inst->context.m_PacketWriter = [inst, callback_context](int af_family, void* data, size_t size) {
        inst->packet_writer(af_family, data, size, callback_context);
        return true;
    };

    inst->context.m_OnReadable = [inst, callback_context](llarp::apple::VPNInterface& iface) {
        inst->iface = iface.weak_from_this();
        inst->start_reading(callback_context);
    };

    std::promise<void> result;
    inst->runner = std::thread{[inst, &result] {
        const llarp::RuntimeOptions opts{};
        try
        {
            inst->context.Setup(opts);
        }
        catch (...)
        {
            result.set_exception(std::current_exception());
            return;
        }
        result.set_value();
        inst->context.Run(opts);
    }};

    try
    {
        result.get_future().get();
    }
    catch (const std::exception& e)
    {
        llarp::LogError("Failed to initialize lokinet: ", e.what());
        return -1;
    }

    return 0;
}

uv_loop_t* llarp_apple_get_uv_loop(void* lokinet)
{
    auto& inst = *static_cast<instance_data*>(lokinet);
    auto uvw = inst.context.loop->MaybeGetUVWLoop();
    assert(uvw);
    return uvw->raw();
}

int llarp_apple_incoming(void* lokinet, const llarp_incoming_packet* packets, size_t size)
{
    auto& inst = *static_cast<instance_data*>(lokinet);

    auto iface = inst.iface.lock();
    if (!iface)
        return -1;

    int count = 0;
    for (size_t i = 0; i < size; i++)
    {
        llarp_buffer_t buf{static_cast<const uint8_t*>(packets[i].bytes), packets[i].size};
        if (iface->OfferReadPacket(buf))
            count++;
        else
            llarp::LogError("invalid IP packet: ", llarp::buffer_printer(buf));
    }

    iface->MaybeWakeUpperLayers();
    return count;
}

void llarp_apple_shutdown(void* lokinet)
{
    auto* inst = static_cast<instance_data*>(lokinet);

    inst->context.CloseAsync();
    inst->context.Wait();
    inst->runner.join();
    delete inst;
}
