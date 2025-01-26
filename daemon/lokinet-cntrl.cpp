#include "utils.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <oxenmq/oxenmq.h>

#include <csignal>

using namespace llarp;
using namespace nlohmann;

namespace llarp::controller
{
    static auto logcat = log::Cat("rpc-controller");

    constexpr auto omq_cat_logger = [](omq::LogLevel /* lvl */, const char* file, int line, std::string buf) {
        std::cout << "[{}:{}] {}"_format(file, line, buf) << std::endl;
    };

    struct rpc_controller
    {
        static std::shared_ptr<rpc_controller> make(omq::LogLevel level)
        {
            return std::shared_ptr<rpc_controller>{new rpc_controller{level}};
        }

      private:
        rpc_controller(omq::LogLevel level) : _omq{std::make_shared<omq::OxenMQ>(omq_cat_logger, level)} {}

        std::shared_ptr<omq::OxenMQ> _omq;
        std::vector<omq::address> _rpc_binds;
        std::unordered_map<omq::address, omq::ConnectionID> _binds;

      public:
        bool start(std::vector<std::string>& bind_addrs)
        {
            _omq->start();

            std::promise<bool> prom{};

            for (auto& b : bind_addrs)
            {
                omq::address bind{b};
                std::cout << "RPC controller connecting to RPC bind address ({})"_format(bind.full_address())
                          << std::endl;
                // log::info(logcat, "RPC controller connecting to RPC bind address ({})", bind.full_address());

                auto cid = _omq->connect_remote(
                    bind,
                    [&](auto) {
                        std::cout << "Loki controller successfully connected to RPC bind ({})"_format(
                            bind.full_address())
                                  << std::endl;
                        prom.set_value(true);
                    },
                    [&](auto, std::string_view msg) {
                        std::cout << "Loki controller failed to connect to RPC bind ({}): {}"_format(
                            bind.full_address(), msg)
                                  << std::endl;
                        prom.set_value(false);
                    });

                _binds.emplace(bind, cid);
            }

            return prom.get_future().get();
        }
    };
}  // namespace llarp::controller

namespace
{
    /**
        Startup CLI options:
        - verbose
        - config file pathways
        - log level
        - loki controller RPC client URL

        Runtime CLI subcommands:
        - list
        - refresh
     */

    struct cli_opts
    {
        bool verbose{false};

        std::vector<std::string> rpc_paths{{"tcp://127.0.0.1:1190"}};

        omq::address rpc_url{};
        std::string log_level{"info"};
        log::Level oxen_log_level{log::Level::info};
    };

    struct app_data
    {
        std::mutex m;
        std::deque<std::string> input_que{};
        std::condition_variable cv;
        std::atomic<bool> running{false};
    };

    enum class switches : int
    {
        LIST = 0,
        REFRESH = 1,
    };

}  // namespace

namespace
{
    static std::shared_ptr<app_data> data;

    auto make_data = []() {
        if (not data)
            data = std::make_shared<app_data>();
    };

    template <typename... T>
    static void exit_error(fmt::format_string<T...> format, T&&... args)
    {
        log::error(controller::logcat, format, std::forward<T>(args)...);
        data->running = false;
        data->cv.notify_all();
    }

    static void app_loop(cli_opts&& options, std::promise<void>&& p)
    {
        auto rpc = controller::rpc_controller::make(oxenlog_to_omq_level(options.oxen_log_level));

        if (not rpc->start(options.rpc_paths))
        {
            std::cout << "RPC controller failed to bind; exiting..." << std::endl;
            p.set_value_at_thread_exit();
            return;
        }

        static thread_local controller::switchboard board{};
        size_t index{};
        std::string address{};

        CLI::App app{};
        app.get_formatter()->column_width(40);
        app.require_subcommand(0, 1);

        // inner app options
        auto* hcom = app.add_subcommand("", "");

        auto* lcom = app.add_subcommand("list", "List all lokinet instances currently running on the local machine");
        lcom->callback([&]() { board.set(switches::LIST); });

        auto* rcom = app.add_subcommand("refresh", "Refresh local lokinet instance information");
        rcom->callback([&]() { board.set(switches::REFRESH); });

        auto* icom = app.add_subcommand("instance", "Select a lokinet instance");
        auto* aopt =
            icom->add_option("-a, --address", address, "Local RPC address of lokinet instance")->type_name("IP:PORT");
        auto* iopt =
            icom->add_option("-i, --index", index, "Index of local lokinet instance (use '-L'/'list' to query!)");

        aopt->excludes(iopt);
        iopt->excludes(aopt);

        // notify startup successful
        data->running = true;
        p.set_value();

        while (data->running)
        {
            try
            {
                std::deque<std::string> copy{};

                {
                    std::unique_lock<std::mutex> lock{data->m, std::defer_lock};
                    data->cv.wait(lock, []() { return !data->input_que.empty() || !data->running; });
                    copy.swap(data->input_que);
                }

                if (!copy.empty())
                {
                    std::cout << "processing input..." << std::endl;
                    while (!copy.empty())
                    {
                        auto line = copy.front();
                        copy.pop_front();
                        std::cout << "line: " << line << std::endl;
                        app.parse(line);
                    }
                }
            }
            catch (const std::exception& e)
            {
                std::cout << "Exception: {}"_format(e.what()) << std::endl;
            }

            app.clear();
        }
    }

    static void input_loop()
    {
        std::cout << "input loop started..." << std::endl;

        std::string input;
        while (data->running)
        {
            std::getline(std::cin, input);

            if (input == "exit")
            {
                data->running = false;
                data->cv.notify_all();
                break;
            }

            {
                std::lock_guard<std::mutex> lock{data->m};
                data->input_que.push_back(std::move(input));
            }

            std::cout << "dispatched..." << std::endl;
            data->cv.notify_all();
        }

        std::cout << "input loop exiting..." << std::endl;
    }
}  // namespace

int main(int argc, char* argv[])
{
    make_data();
    CLI::App cli{"loki controller - lokinet instance control utility", "lokinet-cntrl"};
    cli.get_formatter()->column_width(50);
    cli_opts options{};

    // initial options
    cli.add_flag("-v, --verbose", options.verbose, "Verbose logging (equivalent to passing '--log-level=debug')");
    cli.add_option(
           "-r, --rpc",
           options.rpc_paths,
           "Specify RPC bind addresses for loki controller to connect to (accepts multiple args)")
        ->type_name("PATH(S)")
        ->capture_default_str();
    cli.add_option(
           "-l, --log-level", options.log_level, "Log verbosity level ('error', 'warn', 'info', 'debug', 'trace')")
        ->type_name("LEVEL")
        ->capture_default_str();

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }
    catch (const std::exception& e)
    {
        return cli.exit(CLI::Error{"Exception", e.what()});
    }

    options.oxen_log_level = log::level_from_string(options.log_level);

    if (options.verbose)
        options.oxen_log_level = log::Level::debug;

    log::add_sink(log::Type::Print, "stderr");
    log::reset_level(options.oxen_log_level);

    std::cout << "initializing..." << std::endl;

    try
    {
        std::promise<void> p;
        auto f = p.get_future();

        std::thread app_thread(app_loop, std::move(options), std::move(p));

        f.get();

        std::thread input_thread(input_loop);

        app_thread.join();
        input_thread.join();
    }
    catch (const std::exception& e)
    {
        cli.exit(CLI::Error{"Exception", e.what()});
    }

    return 0;
}
