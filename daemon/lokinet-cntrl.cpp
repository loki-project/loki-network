#include "utils.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <oxenmq/oxenmq.h>

#if defined(__linux__)
extern "C"
{
#include <termios.h>
}
#endif

using namespace llarp;
using namespace nlohmann;

namespace llarp::controller
{
    static auto logcat = log::Cat("rpc-controller");

    constexpr auto omq_cat_logger = [](omq::LogLevel lvl, const char* file, int line, std::string buf) {
        auto msg = "[{}:{}] {}"_format(file, line, buf);

        switch (lvl)
        {
            case oxenmq::LogLevel::fatal:
                log::critical(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::error:
                log::error(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::warn:
                log::warning(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::info:
                log::info(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::debug:
                log::debug(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::trace:
            default:
                log::trace(logcat, "{}", msg);
                break;
        }
    };

    struct lokinet_instance
    {
      private:
        static size_t next_id;

      public:
        lokinet_instance() = delete;
        lokinet_instance(omq::ConnectionID c) : ID{++next_id}, cid{std::move(c)} {}

        const size_t ID;
        omq::ConnectionID cid;
    };

    size_t lokinet_instance::next_id = 0;

    struct rpc_controller
    {
        static std::shared_ptr<rpc_controller> make(omq::LogLevel level)
        {
            return std::shared_ptr<rpc_controller>{new rpc_controller{level}};
        }

      private:
        rpc_controller(omq::LogLevel level) : _omq{std::make_shared<omq::OxenMQ>(omq_cat_logger, level)} {}

        std::shared_ptr<omq::OxenMQ> _omq;
        std::unordered_map<omq::address, lokinet_instance> _binds;
        std::map<size_t, omq::address> _indexes;

        void _initiate(omq::address src, std::string remote)
        {
            log::info(
                logcat,
                "Instructing lokinet instance (bind:{}) to initiate session to remote:{}",
                src.full_address(),
                remote);

            nlohmann::json req;
            req["pk"] = remote;
            req["x"] = false;

            if (auto it = _binds.find(src); it != _binds.end())
                _omq->request(
                    it->second.cid,
                    "llarp.session_init",
                    [&](bool success, std::vector<std::string> data) {
                        if (success)
                        {
                            auto res = nlohmann::json::parse(data[0]);
                            log::info(logcat, "RPC call to initiate session succeeded: {}", res.dump());
                        }
                        else
                            log::critical(logcat, "RPC call to initiate session failed!");
                    },
                    req.dump());
            else
                log::critical(logcat, "Could not find connection ID to RPC bind {}", src.full_address());
        }

        void _status(omq::address src)
        {
            log::info(logcat, "Querying lokinet instance (bind:{}) for router status", src.full_address());

            if (auto it = _binds.find(src); it != _binds.end())
                _omq->request(it->second.cid, "llarp.status", [&](bool success, std::vector<std::string> data) {
                    if (success)
                    {
                        auto res = nlohmann::json::parse(data[0]);
                        log::info(logcat, "RPC call to query router status succeeded: \n{}\n", res.dump(4));
                    }
                    else
                        log::critical(logcat, "RPC call to query router status failed!");
                });
            else
                log::critical(logcat, "Could not find connection ID to RPC bind {}", src.full_address());
        }

      public:
        bool omq_connect(const std::vector<std::string>& bind_addrs)
        {
            int i = 0;
            std::vector<std::promise<bool>> connect_proms{bind_addrs.size()};

            for (auto& b : bind_addrs)
            {
                omq::address bind{b};
                log::info(logcat, "RPC controller connecting to RPC bind address ({})", bind.full_address());

                auto cid = _omq->connect_remote(
                    bind,
                    [&, idx = i](auto) {
                        log::info(
                            logcat, "Loki controller successfully connected to RPC bind ({})", bind.full_address());
                        connect_proms[idx].set_value(true);
                    },
                    [&, idx = i](auto, std::string_view msg) {
                        log::info(
                            logcat, "Loki controller failed to connect to RPC bind ({}): {}", bind.full_address(), msg);
                        connect_proms[idx].set_value(false);
                    });
                auto it = _binds.emplace(bind, lokinet_instance{cid}).first;
                _indexes.emplace(it->second.ID, it->first);
                i += 1;
            }

            bool ret = true;

            for (auto& p : connect_proms)
                ret &= p.get_future().get();

            return ret;
        }

        bool start(std::vector<std::string>& bind_addrs)
        {
            _omq->start();
            return omq_connect(bind_addrs);
        }

        void list_all() const
        {
            auto msg = "\n\n\tLokinet RPC controller connected to {} RPC binds:\n"_format(_binds.size());
            for (auto& [idx, addr] : _indexes)
                msg += "\t\tID:{} | Address:{}\n"_format(idx, addr.full_address());

            log::info(logcat, "{}", msg);
        }

        void refresh() { log::info(logcat, "TODO: implement this!"); }

        void initiate(size_t idx, std::string remote)
        {
            if (auto it = _indexes.find(idx); it != _indexes.end())
                _initiate(it->second, std::move(remote));
            else
                log::warning(logcat, "Could not find instance with given index: {}", idx);
        }

        void initiate(omq::address src, std::string remote) { return _initiate(std::move(src), std::move(remote)); }

        void status(omq::address src) { return _status(std::move(src)); };

        void status(size_t idx)
        {
            if (auto it = _indexes.find(idx); it != _indexes.end())
                _status(it->second);
            else
                log::warning(logcat, "Could not find instance with given index: {}", idx);
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
        - init
        - status
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
            instance_subcom->add_subcommand("init", "Initiate session to a remote client")->require_option(1);
        init_subcom->add_option("-p, --pubkey", pubkey, "PubKey of remote lokinet client");

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

        std::thread app_thread(app_loop, std::move(options), std::move(p));

        f.get();

        std::thread input_thread(input_loop);

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
