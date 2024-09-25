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
        std::shared_ptr<EventLoop> _loop = nullptr;
        std::shared_ptr<NodeDB> nodedb = nullptr;

        Context();
        virtual ~Context() = default;

        void setup(const RuntimeOptions& opts);

        int run(const RuntimeOptions& opts);

        void handle_signal(int sig);

        /// Configure given the specified config.
        void configure(std::shared_ptr<Config> conf);

        /// handle SIGHUP
        void reload();

        bool is_up() const;

        bool looks_alive() const;

        bool is_stopping() const;

        /// close async
        void close_async();

        /// wait until closed and done
        void wait();

        /// call a function in logic thread
        /// return true if queued for calling
        /// return false if not queued for calling
        bool call_safe(std::function<void(void)> f);

        /// Creates a router
        std::shared_ptr<Router> make_router(const std::shared_ptr<EventLoop>& loop, std::promise<void> p);

        /// create the nodedb given our current configs
        // virtual std::shared_ptr<NodeDB> make_nodedb();

        /// create the vpn platform for use in creating network interfaces
        virtual std::shared_ptr<llarp::vpn::Platform> make_vpn_platform();

        int androidFD = -1;

      protected:
        std::shared_ptr<Config> config = nullptr;

      private:
        void signal(int s);

        void close();

        std::unique_ptr<std::promise<void>> close_waiter;

        std::unique_ptr<std::future<void>> loop_waiter;
    };
}  // namespace llarp

#endif
