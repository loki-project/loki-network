#ifndef LLARP_HPP
#define LLARP_HPP

#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace llarp
{
    namespace vpn
    {
        class Platform;
    }
    // Deprecated
    class EvLoop_deprecated;
    // New loop
    class EventLoop;
    struct Config;
    struct RouterContact;
    struct Config;
    struct Router;
    class NodeDB;

    namespace thread
    {
        class ThreadPool;
    }

    struct RuntimeOptions
    {
        bool showBanner = true;
        bool debug = false;
        bool isSNode = false;
    };

    struct Context
    {
        std::shared_ptr<Router> router = nullptr;
        std::shared_ptr<EvLoop_deprecated> loop = nullptr;
        std::shared_ptr<EventLoop> _loop = nullptr;
        std::shared_ptr<NodeDB> nodedb = nullptr;

        Context();
        virtual ~Context() = default;

        void Setup(const RuntimeOptions& opts);

        int Run(const RuntimeOptions& opts);

        void HandleSignal(int sig);

        /// Configure given the specified config.
        void Configure(std::shared_ptr<Config> conf);

        /// handle SIGHUP
        void Reload();

        bool IsUp() const;

        bool LooksAlive() const;

        bool IsStopping() const;

        /// close async
        void CloseAsync();

        /// wait until closed and done
        void Wait();

        /// call a function in logic thread
        /// return true if queued for calling
        /// return false if not queued for calling
        bool CallSafe(std::function<void(void)> f);

        /// Creates a router. Can be overridden to allow a different class of router
        /// to be created instead. Defaults to llarp::Router.
        virtual std::shared_ptr<Router> makeRouter(const std::shared_ptr<EvLoop_deprecated>& loop);

        /// create the nodedb given our current configs
        virtual std::shared_ptr<NodeDB> makeNodeDB();

        /// create the vpn platform for use in creating network interfaces
        virtual std::shared_ptr<llarp::vpn::Platform> makeVPNPlatform();

        int androidFD = -1;

       protected:
        std::shared_ptr<Config> config = nullptr;

       private:
        void SigINT();

        void Close();

        std::unique_ptr<std::promise<void>> closeWaiter;
    };
}  // namespace llarp

#endif
