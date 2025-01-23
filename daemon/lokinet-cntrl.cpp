#include <llarp.hpp>
#include <llarp/util/logging.hpp>

#include <CLI/CLI.hpp>
#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <oxenmq/oxenmq.h>

#include <future>
#include <string_view>
#include <vector>

#ifdef _WIN32
// add the unholy windows headers for iphlpapi
#include <winsock2.h>

#include <iphlpapi.h>
#include <strsafe.h>
#include <ws2tcpip.h>
#else
#endif

using namespace nlohmann;
namespace omq = oxenmq;

/// do a oxenmq request on an omq instance blocking style
/// returns a json object parsed from the result
std::optional<json> omq_request(
    omq::OxenMQ& _omq, const omq::ConnectionID& _id, std::string_view _method, std::optional<json> _args = std::nullopt)
{
    std::promise<std::optional<std::string>> result_promise;

    auto handler = [&result_promise](bool success, std::vector<std::string> result) {
        if ((not success) or result.empty())
            result_promise.set_value(std::nullopt);
        else
            result_promise.set_value(result[0]);
    };

    if (_args.has_value())
    {
        _omq.request(_id, _method, handler, _args->dump());
    }
    else
    {
        _omq.request(_id, _method, handler);
    }

    auto str = result_promise.get_future().get();

    if (str.has_value())
        return json::parse(*str);

    return str;
}

namespace
{
    static auto logcat = llarp::log::Cat("controller");

    /**
            Main CLI interface:
            - verbose
            - config file pathways
            - omq log level

     */

    struct cli_opts
    {
        bool verbose{false};
        std::vector<std::string> config_paths{};

        bool vpn_up{false};
        bool vpn_down{false};
        bool swap{false};
        bool print_status{false};
        bool kill_daemon{false};

        // string options
        std::string rpc;

        // oxenmq
        omq::address rpcURL{};
        omq::LogLevel log_level = omq::LogLevel::info;
    };

    template <typename... T>
    int exit_error(int code, fmt::format_string<T...> format, T&&... args)
    {
        llarp::log::error(logcat, format, std::forward<T>(args)...);
        return code;
    }

    template <typename... T>
    int exit_error(fmt::format_string<T...> format, T&&... args)
    {
        return exit_error(1, format, std::forward<T>(args)...);
    }

}  // namespace

int main(int argc, char* argv[])
{
    CLI::App cli{"loki controller - lokinet instance control utility", "lokinet-cntrl"};
    cli_opts options{};

    // flags: boolean values in command_line_options struct
    cli.add_flag("-v,--verbose", options.verbose, "Verbose logging [equivalent to passing '--log-level=debug']");

    // options: oxenmq values in command_line_options struct
    cli.add_option("--rpc", options.rpc, "Specify RPC URL for lokinet")->capture_default_str();
    cli.add_option(
           "--log-level", options.log_level, "Log verbosity level ['fatal', 'error', 'warn', 'info', 'debug', 'trace']")
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

    try
    {
        if (options.verbose)
            options.log_level = omq::LogLevel::debug;
    }
    catch (const CLI::OptionNotFound& e)
    {
        cli.exit(e);
    }
    catch (const CLI::Error& e)
    {
        cli.exit(e);
    };

    int numCommands = options.vpn_up + options.vpn_down + options.print_status + options.kill_daemon;

    switch (numCommands)
    {
        case 0:
            return exit_error(3, "One of --add/--remove/--swap/--status/--kill must be specified");
        case 1:
            break;
        default:
            return exit_error(3, "Only one of --add/--remove/--swap/--status/--kill may be specified");
    }

    // if (options.vpn_up and options.exit_address.empty())
    //     return exit_error("No exit address provided, must specify --exit <address>");

    omq::OxenMQ omq{
        [](omq::LogLevel lvl, const char* file, int line, std::string msg) {
            std::cout << lvl << " [" << file << ":" << line << "] " << msg << std::endl;
        },
        options.log_level};

    options.rpcURL = omq::address{(options.rpc.empty()) ? "tcp://127.0.0.1:1190" : options.rpc};

    omq.start();

    std::promise<bool> connect_prom;

    const auto connectionID = omq.connect_remote(
        options.rpcURL,
        [&connect_prom](auto) { connect_prom.set_value(true); },
        [&connect_prom](auto, std::string_view msg) {
            std::cout << "Failed to connect to lokinet RPC: " << msg << std::endl;
            connect_prom.set_value(false);
        });

    auto ftr = connect_prom.get_future();
    if (not ftr.get())
        return 1;

    // if (options.print_status)
    // {
    //     const auto maybe_status = OMQ_Request(omq, connectionID, "llarp.status");

    //     if (not maybe_status)
    //         return exit_error("Call to llarp.status failed");

    //     try
    //     {
    //         const auto& ep = maybe_status->at("result").at("services").at(options.endpoint).at("exitMap");

    //         if (ep.empty())
    //         {
    //             std::cout << "No exits found" << std::endl;
    //         }
    //         else
    //         {
    //             for (const auto& [range, exit] : ep.items())
    //             {
    //                 std::cout << range << " via " << exit.get<std::string>() << std::endl;
    //             }
    //         }
    //     }
    //     catch (std::exception& ex)
    //     {
    //         return exit_error("Failed to parse result: {}", ex.what());
    //     }
    //     return 0;
    // }

    return 0;
}
