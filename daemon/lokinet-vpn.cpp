#include <oxenmq/oxenmq.h>
#include <nlohmann/json.hpp>
#include <fmt/core.h>
#include <cxxopts.hpp>
#include <future>
#include <vector>
#include <array>
#include <llarp/net/net.hpp>

#ifdef _WIN32
// add the unholy windows headers for iphlpapi
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <strsafe.h>
#else
#include <sys/wait.h>
#endif

/// do a oxenmq request on an omq instance blocking style
/// returns a json object parsed from the result
std::optional<nlohmann::json>
OMQ_Request(
    oxenmq::OxenMQ& omq,
    const oxenmq::ConnectionID& id,
    std::string_view method,
    std::optional<nlohmann::json> args = std::nullopt)
{
  std::promise<std::optional<std::string>> result_promise;

  auto handleRequest = [&result_promise](bool success, std::vector<std::string> result) {
    if ((not success) or result.empty())
    {
      result_promise.set_value(std::nullopt);
      return;
    }
    result_promise.set_value(result[0]);
  };
  if (args.has_value())
  {
    omq.request(id, method, handleRequest, args->dump());
  }
  else
  {
    omq.request(id, method, handleRequest);
  }
  auto ftr = result_promise.get_future();
  const auto str = ftr.get();
  if (str.has_value())
    return nlohmann::json::parse(*str);
  return std::nullopt;
}

namespace
{
  template <typename T>
  constexpr bool is_optional = false;
  template <typename T>
  constexpr bool is_optional<std::optional<T>> = true;

  // Extracts a value from a cxxopts result and assigns it into `value` if present.  The value can
  // either be a plain value or a std::optional.  If not present, `value` is not touched.
  template <typename T>
  void
  extract_option(const cxxopts::ParseResult& r, const std::string& name, T& value)
  {
    if (r.count(name))
    {
      if constexpr (is_optional<T>)
        value = r[name].as<typename T::value_type>();
      else
        value = r[name].as<T>();
    }
  }

  // Takes a code, prints a message, and returns the code.  Intended use is:
  //     return exit_error(1, "blah: {}", 42);
  // from within main().
  template <typename... T>
  [[nodiscard]] int
  exit_error(int code, const fmt::format_string<T...> format, T&&... args)
  {
    fmt::print(format, std::forward<T>(args)...);
    fmt::print("\n");
    return code;
  }

  // Same as above, but with code omitted (uses exit code 1)
  template <typename... T>
  [[nodiscard]] int
  exit_error(const fmt::format_string<T...>& format, T&&... args)
  {
    return exit_error(1, format, std::forward<T>(args)...);
  }

}  // namespace

int
main(int argc, char* argv[])
{
  cxxopts::Options opts("lokinet-vpn", "LokiNET vpn control utility");

  // clang-format off
  opts.add_options()
    ("v,verbose", "Verbose", cxxopts::value<bool>())
    ("h,help", "help", cxxopts::value<bool>())
    ("kill", "kill the daemon", cxxopts::value<bool>())
    ("up", "put vpn up", cxxopts::value<bool>())
    ("down", "put vpn down", cxxopts::value<bool>())
    ("exit", "specify exit node address", cxxopts::value<std::string>())
    ("rpc", "rpc url for lokinet", cxxopts::value<std::string>())
    ("endpoint", "endpoint to use", cxxopts::value<std::string>())
    ("token", "exit auth token to use", cxxopts::value<std::string>())
    ("auth", "exit auth token to use", cxxopts::value<std::string>())
    ("status", "print status and exit", cxxopts::value<bool>())
    ("range", "ip range to map", cxxopts::value<std::string>())
    ;
  // clang-format on
  oxenmq::address rpcURL("tcp://127.0.0.1:1190");
  std::string exitAddress;
  std::string endpoint = "default";
  std::string token;
  std::optional<std::string> range;
  oxenmq::LogLevel logLevel = oxenmq::LogLevel::warn;
  bool goUp = false;
  bool goDown = false;
  bool printStatus = false;
  bool killDaemon = false;
  try
  {
    const auto result = opts.parse(argc, argv);

    if (result.count("help") > 0)
    {
      std::cout << opts.help() << std::endl;
      return 0;
    }

    if (result.count("verbose") > 0)
    {
      logLevel = oxenmq::LogLevel::debug;
    }
    goUp = result.count("up") > 0;
    goDown = result.count("down") > 0;
    printStatus = result.count("status") > 0;
    killDaemon = result.count("kill") > 0;

    extract_option(result, "rpc", rpcURL);
    extract_option(result, "exit", exitAddress);
    extract_option(result, "endpoint", endpoint);
    extract_option(result, "token", token);
    extract_option(result, "auth", token);
    extract_option(result, "range", range);
  }
  catch (const cxxopts::option_not_exists_exception& ex)
  {
    return exit_error(2, "{}\n{}", ex.what(), opts.help());
  }
  catch (std::exception& ex)
  {
    return exit_error(2, "{}", ex.what());
  }

  int num_commands = goUp + goDown + printStatus + killDaemon;

  if (num_commands == 0)
    return exit_error(3, "One of --up/--down/--status/--kill must be specified");
  if (num_commands != 1)
    return exit_error(3, "Only one of --up/--down/--status/--kill may be specified");

  if (goUp and exitAddress.empty())
    return exit_error("no exit address provided");

  oxenmq::OxenMQ omq{
      [](oxenmq::LogLevel lvl, const char* file, int line, std::string msg) {
        std::cout << lvl << " [" << file << ":" << line << "] " << msg << std::endl;
      },
      logLevel};

  omq.start();

  std::promise<bool> connectPromise;

  const auto connID = omq.connect_remote(
      rpcURL,
      [&connectPromise](auto) { connectPromise.set_value(true); },
      [&connectPromise](auto, std::string_view msg) {
        std::cout << "failed to connect to lokinet RPC: " << msg << std::endl;
        connectPromise.set_value(false);
      });

  auto ftr = connectPromise.get_future();
  if (not ftr.get())
  {
    return 1;
  }

  if (killDaemon)
  {
    if (not OMQ_Request(omq, connID, "llarp.halt"))
      return exit_error("call to llarp.halt failed");
    return 0;
  }

  if (printStatus)
  {
    const auto maybe_status = OMQ_Request(omq, connID, "llarp.status");
    if (not maybe_status)
      return exit_error("call to llarp.status failed");

    try
    {
      const auto& ep = maybe_status->at("result").at("services").at(endpoint);
      const auto exitMap = ep.at("exitMap");
      if (exitMap.empty())
      {
        std::cout << "no exits" << std::endl;
      }
      else
      {
        for (const auto& [range, exit] : exitMap.items())
        {
          std::cout << range << " via " << exit.get<std::string>() << std::endl;
        }
      }
    }
    catch (std::exception& ex)
    {
      return exit_error("failed to parse result: {}", ex.what());
    }
    return 0;
  }
  if (goUp)
  {
    nlohmann::json opts{{"exit", exitAddress}, {"token", token}};
    if (range)
      opts["range"] = *range;

    auto maybe_result = OMQ_Request(omq, connID, "llarp.exit", std::move(opts));

    if (not maybe_result)
      return exit_error("could not add exit");

    if (auto err_it = maybe_result->find("error");
        err_it != maybe_result->end() and not err_it.value().is_null())
    {
      return exit_error("{}", err_it.value().dump());
    }
  }
  if (goDown)
  {
    nlohmann::json opts{{"unmap", true}};
    if (range)
      opts["range"] = *range;
    if (not OMQ_Request(omq, connID, "llarp.exit", std::move(opts)))
      return exit_error("failed to unmap exit");
  }

  return 0;
}
