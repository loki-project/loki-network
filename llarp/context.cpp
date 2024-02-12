#include "nodedb.hpp"

#include <llarp.hpp>
#include <llarp/config/config.hpp>
#include <llarp/constants/version.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/ev/ev.hpp>
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
    bool Context::CallSafe(std::function<void(void)> f)
    {
        if (!loop)
            return false;
        loop->call_soon(std::move(f));
        return true;
    }

    void Context::Configure(std::shared_ptr<Config> conf)
    {
        if (nullptr != config.get())
            throw std::runtime_error{"Config already exists"};

        config = std::move(conf);
    }

    bool Context::IsUp() const
    {
        return router && router->IsRunning();
    }

    bool Context::LooksAlive() const
    {
        return router && router->LooksAlive();
    }

    void Context::Setup(const RuntimeOptions& opts)
    {
        /// Call one of the Configure() methods before calling Setup()
        if (not config)
            throw std::runtime_error{"Cannot call Setup() on context without a Config"};

        if (opts.showBanner)
            llarp::LogInfo(fmt::format("{}", llarp::LOKINET_VERSION_FULL));

        if (!loop)
        {
            auto jobQueueSize = std::max(event_loop_queue_size, config->router.job_que_size);
            loop = EvLoop_deprecated::create(jobQueueSize);
        }

        router = makeRouter(loop);
        nodedb = makeNodeDB();

        if (!router->configure(config, nodedb))
            throw std::runtime_error{"Failed to configure router"};
    }

    std::shared_ptr<NodeDB> Context::makeNodeDB()
    {
        return std::make_shared<NodeDB>(
            nodedb_dirname, [r = router.get()](auto call) { r->queue_disk_io(std::move(call)); }, router.get());
    }

    std::shared_ptr<Router> Context::makeRouter(const std::shared_ptr<EvLoop_deprecated>& loop)
    {
        return std::make_shared<Router>(loop, makeVPNPlatform());
    }

    std::shared_ptr<vpn::Platform> Context::makeVPNPlatform()
    {
        auto plat = vpn::MakeNativePlatform(this);
        if (plat == nullptr)
            throw std::runtime_error{"vpn platform not supported"};
        return plat;
    }

    int Context::Run(const RuntimeOptions&)
    {
        if (router == nullptr)
        {
            // we are not set up so we should die
            llarp::LogError("cannot run non configured context");
            return 1;
        }

        if (not router->run())
            return 2;

        // run net io thread
        llarp::LogInfo("running mainloop");

        loop->run();

        if (closeWaiter)
        {
            closeWaiter->set_value();
        }
        Close();
        return 0;
    }

    void Context::CloseAsync()
    {
        /// already closing
        if (IsStopping())
            return;

        loop->call([this]() { HandleSignal(SIGTERM); });
        closeWaiter = std::make_unique<std::promise<void>>();
    }

    bool Context::IsStopping() const
    {
        return closeWaiter.operator bool();
    }

    void Context::Wait()
    {
        if (closeWaiter)
        {
            closeWaiter->get_future().wait();
            closeWaiter.reset();
        }
    }

    void Context::HandleSignal(int sig)
    {
        llarp::log::debug(logcat, "Handling signal {}", sig);
        if (sig == SIGINT || sig == SIGTERM)
        {
            SigINT();
        }
#ifndef _WIN32
        if (sig == SIGHUP)
        {
            Reload();
        }
#endif
    }

    void Context::Reload()
    {}

    void Context::SigINT()
    {
        if (router)
        {
            llarp::log::error(logcat, "Handling SIGINT");
            /// async stop router on sigint
            router->stop();
        }
    }

    void Context::Close()
    {
        llarp::LogDebug("free config");
        config.reset();

        llarp::LogDebug("free nodedb");
        nodedb.reset();

        llarp::LogDebug("free router");
        router.reset();

        llarp::LogDebug("free loop");
        loop.reset();
    }

    Context::Context()
    {
        // service_manager is a global and context isnt
        llarp::sys::service_manager->give_context(this);
    }

}  // namespace llarp
