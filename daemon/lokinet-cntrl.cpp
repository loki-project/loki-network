#include "utils.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <oxenmq/oxenmq.h>

using namespace llarp;
using namespace nlohmann;

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
        - init
        - status
        - close
     */

    struct cli_opts
    {
        bool verbose{false};

        std::vector<std::string> rpc_paths{
            {"tcp://127.0.0.1:1190"}, {"tcp://127.0.0.1:1189"}, {"tcp://127.0.0.1:1188"}};

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

}  // namespace

namespace
{
    static std::shared_ptr<app_data> runtime_data;

    template <typename... T>
    static int exit_now(bool is_error, fmt::format_string<T...> format, T&&... args)
    {
        if (is_error)
            log::error(controller::logcat, format, std::forward<T>(args)...);
        else
            log::info(controller::logcat, format, std::forward<T>(args)...);

        runtime_data->running = false;
        runtime_data->cv.notify_all();

        return is_error ? 1 : 0;
    }

    auto prefigure = []() -> int {
        if (not runtime_data)
            runtime_data = std::make_shared<app_data>();

        return 0;
    };

    static void app_loop(cli_opts&& options, std::promise<void>&& p)
    {
        auto rpc = controller::rpc_controller::make(oxenlog_to_omq_level(options.oxen_log_level));

        if (not rpc->start(options.rpc_paths))
        {
            log::critical(controller::logcat, "RPC controller failed to bind; exiting...");
            p.set_value_at_thread_exit();
            return;
        }

        size_t index{};
        std::string address{};
        std::string pubkey{};

        CLI::App app{};
        auto app_fmt = app.get_formatter();
        app_fmt->column_width(40);
        app.set_help_flag("");

        // inner app options
        auto* hcom = app.add_subcommand("help", "Print help menu")->silent();
        hcom->callback([&]() {
                app.clear();
                std::cout << app.help("", CLI::AppFormatMode::Normal) << std::endl;
                for (auto& com : app.get_subcommands(nullptr))
                {
                    std::cout << com->help("", CLI::AppFormatMode::Sub) << std::endl;
                    for (auto& c : com->get_subcommands(nullptr))
                        std::cout << c->help("", CLI::AppFormatMode::Sub) << std::endl;
                }
            })
            ->immediate_callback();

        auto* list_subcom =
            app.add_subcommand("list", "List all lokinet instances currently running on the local machine");
        list_subcom->callback([&]() { rpc->list_all(); })->immediate_callback();

        auto* refresh_subcom = app.add_subcommand("refresh", "Refresh local lokinet instance information");
        refresh_subcom->callback([&]() { rpc->refresh(); });

        auto* instance_subcom =
            app.add_subcommand("instance", "Select a lokinet instance")->require_option(1)->require_subcommand(1);
        auto* aopt = instance_subcom->add_option("-a, --address", address, "Local RPC address of lokinet instance")
                         ->type_name("IP:PORT");
        auto* iopt =
            instance_subcom->add_option("-i, --index", index, "Index of local lokinet instance (use 'list' to query!)");

        aopt->excludes(iopt);
        iopt->excludes(aopt);

        auto* init_subcom =
            instance_subcom->add_subcommand("init", "Initiate session to a remote instance")->require_option(1);
        init_subcom->add_option("-p, --pubkey", pubkey, "PubKey of remote lokinet instance");

        init_subcom->callback([&]() {
            if (not address.empty())
                rpc->initiate(omq::address{std::move(address)}, std::move(pubkey));
            else
                rpc->initiate(index, std::move(pubkey));
        });

        auto* status_subcom = instance_subcom->add_subcommand("status", "Query status of local lokinet instance");

        status_subcom->callback([&]() {
            if (not address.empty())
                rpc->status(omq::address{std::move(address)});
            else
                rpc->status(index);
        });

        auto* close_subcom =
            instance_subcom->add_subcommand("close", "Close session to a remote instance")->require_option(1);
        close_subcom->add_option("-p, --pubkey", pubkey, "PubKey of remote lokinet instance");

        close_subcom->callback([&]() {
            if (not address.empty())
                rpc->close(omq::address{std::move(address)}, std::move(pubkey));
            else
                rpc->close(index, std::move(pubkey));
        });

        // notify startup successful
        runtime_data->running = true;
        p.set_value();

        while (runtime_data->running)
        {
            try
            {
                std::deque<std::string> copy{};

                {
                    std::unique_lock<std::mutex> lock{runtime_data->m, std::defer_lock};
                    runtime_data->cv.wait(
                        lock, []() { return !runtime_data->input_que.empty() || !runtime_data->running; });
                    copy.swap(runtime_data->input_que);
                }

                if (!copy.empty())
                {
                    log::debug(controller::logcat, "processing input...");
                    while (!copy.empty())
                    {
                        auto line = copy.front();
                        copy.pop_front();
                        log::debug(controller::logcat, "input: {}", line);
                        app.parse(line);
                    }
                }
            }
            catch (const std::exception& e)
            {
                log::warning(controller::logcat, "Exception: {}", e.what());
            }

            app.clear();
        }
    }

    static void input_loop()
    {
        log::info(controller::logcat, "input loop started...");

        std::string input;
        while (runtime_data->running)
        {
            std::getline(std::cin, input);

            if (input == "exit")
            {
                runtime_data->running = false;
                runtime_data->cv.notify_all();
                break;
            }

            {
                std::lock_guard<std::mutex> lock{runtime_data->m};
                runtime_data->input_que.push_back(std::move(input));
            }

            log::debug(controller::logcat, "dispatched...");
            runtime_data->cv.notify_all();
        }

        log::info(controller::logcat, "input loop exiting...");
    }
}  // namespace

int main(int argc, char* argv[])
{
    if (auto rv = prefigure(); rv != 0)
        return rv;

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
        return exit_now(true, "Exception: {}", e.what());
    }
    catch (const std::exception& e)
    {
        return exit_now(true, "Exception: {}", e.what());
    }

    options.oxen_log_level = log::level_from_string(options.log_level);

    if (options.verbose)
        options.oxen_log_level = log::Level::debug;

    log::add_sink(log::Type::Print, "stderr");
    log::reset_level(options.oxen_log_level);

    log::info(controller::logcat, "initializing...");

    try
    {
        std::promise<void> p;
        auto f = p.get_future();

        std::thread app_thread{app_loop, std::move(options), std::move(p)};

        f.get();

        std::thread input_thread{input_loop};

        app_thread.join();
        input_thread.join();
    }
    catch (const std::exception& e)
    {
        return exit_now(true, "Exception: {}", e.what());
    }

    log::info(controller::logcat, "exiting...");
    return 0;
}
