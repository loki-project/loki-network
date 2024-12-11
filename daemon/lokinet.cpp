#include <llarp/config/config.hpp>  // for ensure_config
#include <llarp/constants/version.hpp>
#include <llarp.hpp>
#include <llarp/util/lokinet_init.h>
#include <llarp/util/exceptions.hpp>
#include <llarp/util/fs.hpp>
#include <llarp/util/str.hpp>

#ifdef _WIN32
#include <llarp/win32/service_manager.hpp>
#include <dbghelp.h>
#else
#include <llarp/util/service_manager.hpp>
#endif

#include <csignal>

#include <cxxopts.hpp>
#include <string>
#include <iostream>
#include <future>

int
lokinet_main(int, char**);

#ifdef _WIN32
extern "C" LONG FAR PASCAL
win32_signal_handler(EXCEPTION_POINTERS*);
extern "C" VOID FAR PASCAL
win32_daemon_entry(DWORD, LPTSTR*);

VOID
insert_description();

#endif

static auto logcat = llarp::log::Cat("main");
std::shared_ptr<llarp::Context> ctx;
std::promise<int> exit_code;

void
handle_signal(int sig)
{
  llarp::log::info(logcat, "Handling signal {}", sig);
  if (ctx)
    ctx->loop->call([sig] { ctx->HandleSignal(sig); });
  else
    std::cerr << "Received signal " << sig << ", but have no context yet. Ignoring!" << std::endl;
}

#ifdef _WIN32
int
startWinsock()
{
  WSADATA wsockd;
  int err;
  err = ::WSAStartup(MAKEWORD(2, 2), &wsockd);
  if (err)
  {
    perror("Failed to start Windows Sockets");
    return err;
  }
  ::CreateMutex(nullptr, FALSE, "lokinet_win32_daemon");
  return 0;
}

extern "C" BOOL FAR PASCAL
handle_signal_win32(DWORD fdwCtrlType)
{
  UNREFERENCED_PARAMETER(fdwCtrlType);
  handle_signal(SIGINT);
  return TRUE;  // probably unreachable
}

void
install_win32_daemon()
{
  SC_HANDLE schSCManager;
  SC_HANDLE schService;
  std::array<char, 1024> szPath{};

  if (!GetModuleFileName(nullptr, szPath.data(), MAX_PATH))
  {
    llarp::LogError("Cannot install service ", GetLastError());
    return;
  }

  // Get a handle to the SCM database.
  schSCManager = OpenSCManager(
      nullptr,                 // local computer
      nullptr,                 // ServicesActive database
      SC_MANAGER_ALL_ACCESS);  // full access rights

  if (nullptr == schSCManager)
  {
    llarp::LogError("OpenSCManager failed ", GetLastError());
    return;
  }

  // Create the service
  schService = CreateService(
      schSCManager,               // SCM database
      strdup("lokinet"),          // name of service
      "Lokinet for Windows",      // service name to display
      SERVICE_ALL_ACCESS,         // desired access
      SERVICE_WIN32_OWN_PROCESS,  // service type
      SERVICE_DEMAND_START,       // start type
      SERVICE_ERROR_NORMAL,       // error control type
      szPath.data(),              // path to service's binary
      nullptr,                    // no load ordering group
      nullptr,                    // no tag identifier
      nullptr,                    // no dependencies
      nullptr,                    // LocalSystem account
      nullptr);                   // no password

  if (schService == nullptr)
  {
    llarp::LogError("CreateService failed ", GetLastError());
    CloseServiceHandle(schSCManager);
    return;
  }
  else
    llarp::LogInfo("Service installed successfully");

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
  insert_description();
}

VOID
insert_description()
{
  SC_HANDLE schSCManager;
  SC_HANDLE schService;
  SERVICE_DESCRIPTION sd;
  LPTSTR szDesc = strdup(
      "LokiNET is a free, open source, private, "
      "decentralized, \"market based sybil resistant\" "
      "and IP based onion routing network");
  // Get a handle to the SCM database.
  schSCManager = OpenSCManager(
      NULL,                    // local computer
      NULL,                    // ServicesActive database
      SC_MANAGER_ALL_ACCESS);  // full access rights

  if (nullptr == schSCManager)
  {
    llarp::LogError("OpenSCManager failed ", GetLastError());
    return;
  }

  // Get a handle to the service.
  schService = OpenService(
      schSCManager,            // SCM database
      "lokinet",               // name of service
      SERVICE_CHANGE_CONFIG);  // need change config access

  if (schService == nullptr)
  {
    llarp::LogError("OpenService failed ", GetLastError());
    CloseServiceHandle(schSCManager);
    return;
  }

  // Change the service description.
  sd.lpDescription = szDesc;

  if (!ChangeServiceConfig2(
          schService,                  // handle to service
          SERVICE_CONFIG_DESCRIPTION,  // change: description
          &sd))                        // new description
  {
    llarp::LogError("ChangeServiceConfig2 failed");
  }
  else
    llarp::LogInfo("Service description updated successfully.");

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
}

void
uninstall_win32_daemon()
{
  SC_HANDLE schSCManager;
  SC_HANDLE schService;

  // Get a handle to the SCM database.
  schSCManager = OpenSCManager(
      nullptr,                 // local computer
      nullptr,                 // ServicesActive database
      SC_MANAGER_ALL_ACCESS);  // full access rights

  if (nullptr == schSCManager)
  {
    llarp::LogError("OpenSCManager failed ", GetLastError());
    return;
  }

  // Get a handle to the service.
  schService = OpenService(
      schSCManager,  // SCM database
      "lokinet",     // name of service
      0x10000);      // need delete access

  if (schService == nullptr)
  {
    llarp::LogError("OpenService failed ", GetLastError());
    CloseServiceHandle(schSCManager);
    return;
  }

  // Delete the service.
  if (!DeleteService(schService))
  {
    llarp::LogError("DeleteService failed ", GetLastError());
  }
  else
    llarp::LogInfo("Service deleted successfully\n");

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
}
#endif

/// this sets up, configures and runs the main context
static void
run_main_context(std::optional<fs::path> confFile, const llarp::RuntimeOptions opts)
{
  llarp::LogInfo(fmt::format("starting up {} {}", llarp::VERSION_FULL, llarp::RELEASE_MOTTO));
  try
  {
    std::shared_ptr<llarp::Config> conf;
    if (confFile)
    {
      llarp::LogInfo("Using config file: ", *confFile);
      conf = std::make_shared<llarp::Config>(confFile->parent_path());
    }
    else
    {
      conf = std::make_shared<llarp::Config>(llarp::GetDefaultDataDir());
    }
    if (not conf->Load(confFile, opts.isSNode))
    {
      llarp::LogError("failed to parse configuration");
      exit_code.set_value(1);
      return;
    }

    ctx = std::make_shared<llarp::Context>();
    ctx->Configure(std::move(conf));

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#ifndef _WIN32
    signal(SIGHUP, handle_signal);
    signal(SIGUSR1, handle_signal);
#endif

    try
    {
      ctx->Setup(opts);
    }
    catch (llarp::util::bind_socket_error& ex)
    {
      llarp::LogError(fmt::format("{}, is lokinet already running? 🤔", ex.what()));
      exit_code.set_value(1);
      return;
    }
    catch (std::exception& ex)
    {
      llarp::LogError(fmt::format("failed to start up lokinet: {}", ex.what()));
      exit_code.set_value(1);
      return;
    }
    llarp::util::SetThreadName("llarp-mainloop");

    auto result = ctx->Run(opts);
    exit_code.set_value(result);
  }
  catch (std::exception& e)
  {
    llarp::LogError("Fatal: caught exception while running: ", e.what());
    exit_code.set_exception(std::current_exception());
  }
  catch (...)
  {
    llarp::LogError("Fatal: caught non-standard exception while running");
    exit_code.set_exception(std::current_exception());
  }
}

#ifdef _WIN32

/// minidump generation for windows jizz
/// will make a coredump when there is an unhandled exception
LONG
GenerateDump(EXCEPTION_POINTERS* pExceptionPointers)
{
  const auto flags =
      (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithThreadInfo);

  std::stringstream ss;
  ss << "C:\\ProgramData\\lokinet\\crash-" << llarp::time_now_ms().count() << ".dmp";
  const std::string fname = ss.str();
  HANDLE hDumpFile;
  SYSTEMTIME stLocalTime;
  GetLocalTime(&stLocalTime);
  MINIDUMP_EXCEPTION_INFORMATION ExpParam{};

  hDumpFile = CreateFile(
      fname.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_WRITE | FILE_SHARE_READ,
      0,
      CREATE_ALWAYS,
      0,
      0);

  ExpParam.ExceptionPointers = pExceptionPointers;
  ExpParam.ClientPointers = TRUE;

  MiniDumpWriteDump(
      GetCurrentProcess(), GetCurrentProcessId(), hDumpFile, flags, &ExpParam, NULL, NULL);

  return 1;
}

#endif

int
main(int argc, char* argv[])
{
  // Set up a default, stderr logging for very early logging; we'll replace this later once we read
  // the desired log info from config.
  llarp::log::add_sink(llarp::log::Type::Print, "stderr");
  llarp::log::reset_level(llarp::log::Level::info);

  llarp::logRingBuffer = std::make_shared<llarp::log::RingBufferSink>(100);
  llarp::log::add_sink(llarp::logRingBuffer, llarp::log::DEFAULT_PATTERN_MONO);

#ifndef _WIN32
  return lokinet_main(argc, argv);
#else
  SERVICE_TABLE_ENTRY DispatchTable[] = {
      {strdup("lokinet"), (LPSERVICE_MAIN_FUNCTION)win32_daemon_entry}, {NULL, NULL}};

  // Try first to run as a service; if this works it fires off to win32_daemon_entry and doesn't
  // return until the service enters STOPPED state.
  if (StartServiceCtrlDispatcher(DispatchTable))
    return 0;

  auto error = GetLastError();

  // We'll get this error if not invoked as a service, which is fine: we can just run directly
  if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
  {
    llarp::sys::service_manager->disable();
    return lokinet_main(argc, argv);
  }
  else
  {
    llarp::log::critical(
        logcat, "Error launching service: {}", std::system_category().message(error));
    return 1;
  }
#endif
}

int
lokinet_main(int argc, char** argv)
{
  if (auto result = Lokinet_INIT())
    return result;

  llarp::RuntimeOptions opts;
  opts.showBanner = false;

#ifdef _WIN32
  if (startWinsock())
    return -1;
  SetConsoleCtrlHandler(handle_signal_win32, TRUE);
#endif

  cxxopts::Options options(
      "lokinet",
      "LokiNET is a free, open source, private, "
      "decentralized, \"market based sybil resistant\" "
      "and IP based onion routing network");
  // clang-format off
  options.add_options()
#ifdef _WIN32
      ("install", "install win32 daemon to SCM", cxxopts::value<bool>())
      ("remove", "remove win32 daemon from SCM", cxxopts::value<bool>())
#endif
      ("h,help", "print this help message", cxxopts::value<bool>())
      ("version", "print version string", cxxopts::value<bool>())
      ("g,generate", "generate default configuration and exit", cxxopts::value<bool>())
      ("r,router", "run in routing mode instead of client only mode", cxxopts::value<bool>())
      ("f,force", "force writing config even if it already exists", cxxopts::value<bool>())
      ("config", "path to lokinet.ini configuration file", cxxopts::value<std::string>())
      ;
  // clang-format on

  options.parse_positional("config");

  bool genconfigOnly = false;
  bool overwrite = false;
  std::optional<fs::path> configFile;
  try
  {
    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
      std::cout << options.help() << std::endl;
      return 0;
    }
    if (result.count("version"))
    {
      std::cout << llarp::VERSION_FULL << std::endl;
      return 0;
    }
#ifdef _WIN32
    if (result.count("install"))
    {
      install_win32_daemon();
      return 0;
    }

    if (result.count("remove"))
    {
      uninstall_win32_daemon();
      return 0;
    }
#endif
    if (result.count("generate") > 0)
    {
      genconfigOnly = true;
    }

    if (result.count("router") > 0)
    {
      opts.isSNode = true;
    }

    if (result.count("force") > 0)
    {
      overwrite = true;
    }

    if (result.count("config") > 0)
    {
      auto arg = result["config"].as<std::string>();
      if (!arg.empty())
      {
        configFile = arg;
      }
    }
  }
  catch (const cxxopts::option_not_exists_exception& ex)
  {
    std::cerr << ex.what();
    std::cout << options.help() << std::endl;
    return 1;
  }

  if (configFile.has_value())
  {
    // when we have an explicit filepath
    fs::path basedir = configFile->parent_path();
    if (genconfigOnly)
    {
      try
      {
        llarp::ensureConfig(basedir, *configFile, overwrite, opts.isSNode);
      }
      catch (std::exception& ex)
      {
        llarp::LogError("cannot generate config at ", *configFile, ": ", ex.what());
        return 1;
      }
    }
    else
    {
      try
      {
        if (!fs::exists(*configFile))
        {
          llarp::LogError("Config file not found ", *configFile);
          return 1;
        }
      }
      catch (std::exception& ex)
      {
        llarp::LogError("cannot check if ", *configFile, " exists: ", ex.what());
        return 1;
      }
    }
  }
  else
  {
    try
    {
      llarp::ensureConfig(
          llarp::GetDefaultDataDir(), llarp::GetDefaultConfigPath(), overwrite, opts.isSNode);
    }
    catch (std::exception& ex)
    {
      llarp::LogError("cannot ensure config: ", ex.what());
      return 1;
    }
    configFile = llarp::GetDefaultConfigPath();
  }

  if (genconfigOnly)
  {
    return 0;
  }

#ifdef _WIN32
  SetUnhandledExceptionFilter(&GenerateDump);
#endif

  std::thread main_thread{[configFile, opts] { run_main_context(configFile, opts); }};
  auto ftr = exit_code.get_future();

  do
  {
    // do periodic non lokinet related tasks here
    if (ctx and ctx->IsUp() and not ctx->LooksAlive())
    {
      auto deadlock_cat = llarp::log::Cat("deadlock");
      for (const auto& wtf :
           {"you have been visited by the mascott of the deadlocked router.",
            "⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠄⠄⠄⠄",
            "⠄⠄⠄⠄⠄⢀⣀⣀⡀⠄⠄⠄⡠⢲⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠄⠄",
            "⠄⠄⠄⠔⣈⣀⠄⢔⡒⠳⡴⠊⠄⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣧⠄⠄",
            "⠄⢜⡴⢑⠖⠊⢐⣤⠞⣩⡇⠄⠄⠄⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠄⠝⠛⠋⠐",
            "⢸⠏⣷⠈⠄⣱⠃⠄⢠⠃⠐⡀⠄⠄⠄⠄⠙⠻⢿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠸⠄⠄⠄⠄",
            "⠈⣅⠞⢁⣿⢸⠘⡄⡆⠄⠄⠈⠢⡀⠄⠄⠄⠄⠄⠄⠉⠙⠛⠛⠛⠉⠉⡀⠄⠡⢀⠄⣀",
            "⠄⠙⡎⣹⢸⠄⠆⢘⠁⠄⠄⠄⢸⠈⠢⢄⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠃⠄⠄⠄⠄⠄",
            "⠄⠄⠑⢿⠈⢆⠘⢼⠄⠄⠄⠄⠸⢐⢾⠄⡘⡏⠲⠆⠠⣤⢤⢤⡤⠄⣖⡇⠄⠄⠄⠄⠄",
            "⣴⣶⣿⣿⣣⣈⣢⣸⠄⠄⠄⠄⡾⣷⣾⣮⣤⡏⠁⠘⠊⢠⣷⣾⡛⡟⠈⠄⠄⠄⠄⠄⠄",
            "⣿⣿⣿⣿⣿⠉⠒⢽⠄⠄⠄⠄⡇⣿⣟⣿⡇⠄⠄⠄⠄⢸⣻⡿⡇⡇⠄⠄⠄⠄⠄⠄⠄",
            "⠻⣿⣿⣿⣿⣄⠰⢼⠄⠄⠄⡄⠁⢻⣍⣯⠃⠄⠄⠄⠄⠈⢿⣻⠃⠈⡆⡄⠄⠄⠄⠄⠄",
            "⠄⠙⠿⠿⠛⣿⣶⣤⡇⠄⠄⢣⠄⠄⠈⠄⢠⠂⠄⠁⠄⡀⠄⠄⣀⠔⢁⠃⠄⠄⠄⠄⠄",
            "⠄⠄⠄⠄⠄⣿⣿⣿⣿⣾⠢⣖⣶⣦⣤⣤⣬⣤⣤⣤⣴⣶⣶⡏⠠⢃⠌⠄⠄⠄⠄⠄⠄",
            "⠄⠄⠄⠄⠄⠿⠿⠟⠛⡹⠉⠛⠛⠿⠿⣿⣿⣿⣿⣿⡿⠂⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄",
            "⠠⠤⠤⠄⠄⣀⠄⠄⠄⠑⠠⣤⣀⣀⣀⡘⣿⠿⠙⠻⡍⢀⡈⠂⠄⠄⠄⠄⠄⠄⠄⠄⠄",
            "⠄⠄⠄⠄⠄⠄⠑⠠⣠⣴⣾⣿⣿⣿⣿⣿⣿⣇⠉⠄⠻⣿⣷⣄⡀⠄⠄⠄⠄⠄⠄⠄⠄",
            "file a bug report now or be cursed with this "
            "annoying image in your syslog for all time."})
      {
        llarp::log::critical(deadlock_cat, "{}", wtf);
        llarp::log::flush();
      }
      llarp::sys::service_manager->failed();
      std::abort();
    }
  } while (ftr.wait_for(std::chrono::seconds(1)) != std::future_status::ready);

  main_thread.join();

  int code = 0;

  try
  {
    code = ftr.get();
  }
  catch (const std::exception& e)
  {
    std::cerr << "main thread threw exception: " << e.what() << std::endl;
    code = 1;
  }
  catch (...)
  {
    std::cerr << "main thread threw non-standard exception" << std::endl;
    code = 2;
  }

  llarp::log::flush();
  llarp::sys::service_manager->stopped();
  if (ctx)
  {
    ctx.reset();
  }
  return code;
}

#ifdef _WIN32

VOID FAR PASCAL
SvcCtrlHandler(DWORD dwCtrl)
{
  // Handle the requested control code.

  switch (dwCtrl)
  {
    case SERVICE_CONTROL_STOP:
      // tell service we are stopping
      llarp::log::debug(logcat, "Windows service controller gave SERVICE_CONTROL_STOP");
      llarp::sys::service_manager->system_changed_our_state(llarp::sys::ServiceState::Stopping);
      handle_signal(SIGINT);
      return;

    case SERVICE_CONTROL_INTERROGATE:
      // report status
      llarp::log::debug(logcat, "Got win32 service interrogate signal");
      llarp::sys::service_manager->report_changed_state();
      return;

    default:
      llarp::log::debug(logcat, "Got win32 unhandled signal {}", dwCtrl);
      break;
  }
}

// The win32 daemon entry point is where we go when invoked as a windows service; we do the required
// service dance and then pretend we were invoked via main().
VOID FAR PASCAL
win32_daemon_entry(DWORD, LPTSTR* argv)
{
  // Register the handler function for the service
  auto* svc = dynamic_cast<llarp::sys::SVC_Manager*>(llarp::sys::service_manager);
  svc->handle = RegisterServiceCtrlHandler("lokinet", SvcCtrlHandler);

  if (svc->handle == nullptr)
  {
    llarp::LogError("failed to register daemon control handler");
    return;
  }

  // we hard code the args to lokinet_main.
  // we yoink argv[0] (lokinet.exe path) and pass in the new args.
  std::array args = {
      reinterpret_cast<char*>(argv[0]),
      reinterpret_cast<char*>(strdup("c:\\programdata\\lokinet\\lokinet.ini")),
      reinterpret_cast<char*>(0)};
  lokinet_main(args.size() - 1, args.data());
}
#endif
