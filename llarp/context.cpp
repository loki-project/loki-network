#include "nodedb.hpp"

#include <llarp.hpp>
#include <llarp/config/config.hpp>
#include <llarp/constants/version.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/ev/loop.hpp>
#include <llarp/handlers/tun.hpp>
#include <llarp/link/link_manager.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/service_manager.hpp>

#include <csignal>
#include <memory>
#include <stdexcept>

#if (__FreeBSD__) || (__OpenBSD__) || (__NetBSD__)
#include <pthread_np.h>
#endif

namespace llarp
{
    bool Context::call_safe(std::function<void(void)> f)
    {
        if (!_loop)
            return false;
        _loop->call_soon(std::move(f));
        return true;
    }

    void Context::configure(std::shared_ptr<Config> conf)
    {
        if (nullptr != config.get())
            throw std::runtime_error{"Config already exists"};

        config = std::move(conf);
    }

    bool Context::is_up() const
    {
        return router && router->is_running();
    }

    bool Context::looks_alive() const
    {
        return router && router->looks_alive();
    }

    void Context::setup(const RuntimeOptions& opts)
    {
        /// Call one of the Configure() methods before calling Setup()
        if (not config)
            throw std::runtime_error{"Cannot call Setup() on context without a Config"};

        if (opts.showBanner)
            log::info(logcat, "{}", llarp::LOKINET_VERSION_FULL);

        // TODO: configurable job queue size?
        if (!_loop)
        {
            log::info(logcat, "Initializing event loop...");
            _loop = EventLoop::make();
            log::debug(logcat, "Event loop initialized!");
        }

        log::info(logcat, "Making main router...");
        router = make_router(_loop);

        log::info(logcat, "Making local nodeDB instance...");
        nodedb = make_nodedb();

        if (!router->configure(config, nodedb))
            throw std::runtime_error{"Failed to configure router"};
    }

    std::shared_ptr<NodeDB> Context::make_nodedb()
    {
        return std::make_shared<NodeDB>(
            nodedb_dirname, [r = router.get()](auto call) { r->queue_disk_io(std::move(call)); }, router.get());
    }

    std::shared_ptr<Router> Context::make_router(const std::shared_ptr<EventLoop>& loop)
    {
        return std::make_shared<Router>(loop, make_vpn_platform());
    }

    std::shared_ptr<vpn::Platform> Context::make_vpn_platform()
    {
        auto plat = vpn::MakeNativePlatform(this);
        if (plat == nullptr)
            throw std::runtime_error{"vpn platform not supported"};
        return plat;
    }

    int Context::run(const RuntimeOptions&)
    {
        if (router == nullptr)
        {
            // we are not set up so we should die
            log::error(logcat, "ERROR cannot run non-configured context!");
            return 1;
        }

        if (not router->run())
            return 2;

        if (closeWaiter)
        {
            closeWaiter->set_value();
        }
        close();
        return 0;
    }

    void Context::close_async()
    {
        /// already closing
        if (is_stopping())
            return;

        _loop->call([this]() { handle_signal(SIGTERM); });
        closeWaiter = std::make_unique<std::promise<void>>();
    }

    bool Context::is_stopping() const
    {
        return closeWaiter.operator bool();
    }

    void Context::wait()
    {
        if (closeWaiter)
        {
            closeWaiter->get_future().wait();
            closeWaiter.reset();
        }
    }

    void Context::handle_signal(int sig)
    {
        log::debug(logcat, "Handling signal {}", sig);
        if (sig == SIGINT || sig == SIGTERM)
        {
            sigINT();
        }
#ifndef _WIN32
        if (sig == SIGHUP)
        {
            reload();
        }
#endif
    }

    void Context::reload()
    {}

    void Context::sigINT()
    {
        if (router)
        {
            log::error(logcat, "Handling SIGINT");
            /// async stop router on sigint
            router->stop();
        }
    }

    void Context::close()
    {
        log::debug(logcat, "Freeing config");
        config.reset();

        log::debug(logcat, "Freeing local nodeDB");
        nodedb.reset();

        log::debug(logcat, "Freeing main router");
        router.reset();

        log::debug(logcat, "Freeing event loop");
        _loop.reset();
    }

    Context::Context()
    {
        // service_manager is a global and context isnt
        llarp::sys::service_manager->give_context(this);
    }

}  // namespace llarp
