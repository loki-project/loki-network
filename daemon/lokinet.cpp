#include <llarp/config/config.hpp>  // for ensure_config
#include <llarp/constants/version.hpp>
#include <llarp.hpp>
#include <llarp/util/lokinet_init.h>
#include <llarp/util/fs.hpp>
#include <llarp/util/logging/logger.hpp>
#include <llarp/util/logging/ostream_logger.hpp>
#include <llarp/util/str.hpp>

#ifdef _WIN32
#include <dbghelp.h>
#endif

#include <csignal>

#include <cxxopts.hpp>
#include <string>
#include <iostream>
#include <future>

int
lokinet_main(int, char**);

#ifdef _WIN32
#include <strsafe.h>
extern "C" LONG FAR PASCAL
win32_signal_handler(EXCEPTION_POINTERS*);
extern "C" VOID FAR PASCAL
win32_daemon_entry(DWORD, LPTSTR*);
BOOL ReportSvcStatus(DWORD, DWORD, DWORD);
VOID
insert_description();
SERVICE_STATUS SvcStatus;
SERVICE_STATUS_HANDLE SvcStatusHandle;
bool start_as_daemon = false;
#endif

std::shared_ptr<llarp::Context> ctx;
std::promise<int> exit_code;

void
handle_signal(int sig)
{
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
  // just put the flag here. we eat it later on and specify the
  // config path in the daemon entry point
  StringCchCat(szPath.data(), 1024, " --win32-daemon");

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
      "lokinet",                  // name of service
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
  const std::string szDesc{
      "LokiNET is a free, open source, private, "
      "decentralized, \"market based sybil resistant\" "
      "and IP based onion routing network"};
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
  sd.lpDescription = strdup(szDesc.c_str());

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
  llarp::LogTrace("start of run_main_context()");
  try
  {
    std::shared_ptr<llarp::Config> conf;
    if (confFile.has_value())
    {
      llarp::LogInfo("Using config file: ", *confFile);
      conf = std::make_shared<llarp::Config>(confFile->parent_path());
    }
    else
    {
      conf = std::make_shared<llarp::Config>(llarp::GetDefaultDataDir());
    }
    if (!conf->Load(confFile, opts.isSNode))
      throw std::runtime_error{"Config file parsing failed"};

    ctx = std::make_shared<llarp::Context>();
    ctx->Configure(std::move(conf));

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#ifndef _WIN32
    signal(SIGHUP, handle_signal);
    signal(SIGUSR1, handle_signal);
#endif

    ctx->Setup(opts);

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
void
TellWindowsServiceStopped()
{
  ::WSACleanup();
  if (not start_as_daemon)
    return;

  llarp::LogInfo("Telling Windows the service has stopped.");
  if (not ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0))
  {
    auto error_code = GetLastError();
    if (error_code == ERROR_INVALID_DATA)
      llarp::LogError(
          "SetServiceStatus failed: \"The specified service status structure is invalid.\"");
    else if (error_code == ERROR_INVALID_HANDLE)
      llarp::LogError("SetServiceStatus failed: \"The specified handle is invalid.\"");
    else
      llarp::LogError("SetServiceStatus failed with an unknown error.");
  }
  llarp::LogContext::Instance().ImmediateFlush();
}

class WindowsServiceStopped
{
 public:
  WindowsServiceStopped() = default;

  ~WindowsServiceStopped()
  {
    TellWindowsServiceStopped();
  }
};

/// minidump generation for windows jizz
/// will make a coredump when there is an unhandled exception
LONG
GenerateDump(EXCEPTION_POINTERS* pExceptionPointers)
{
  const MINIDUMP_TYPE flags{MiniDumpWithThreadInfo};

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
#ifndef _WIN32
  return lokinet_main(argc, argv);
#else
  SERVICE_TABLE_ENTRY DispatchTable[] = {
      {strdup("lokinet"), (LPSERVICE_MAIN_FUNCTION)win32_daemon_entry}, {NULL, NULL}};
  if (lstrcmpi(argv[1], "--win32-daemon") == 0)
  {
    start_as_daemon = true;
    StartServiceCtrlDispatcher(DispatchTable);
  }
  else
    return lokinet_main(argc, argv);
#endif
}

int
lokinet_main(int argc, char* argv[])
{
  auto result = Lokinet_INIT();
  if (result)
  {
    return result;
  }
  llarp::RuntimeOptions opts;

#ifdef _WIN32
  WindowsServiceStopped stopped_raii;
  if (startWinsock())
    return -1;
  SetConsoleCtrlHandler(handle_signal_win32, TRUE);

  // SetUnhandledExceptionFilter(win32_signal_handler);
#endif
  cxxopts::Options options(
      "lokinet",
      "LokiNET is a free, open source, private, "
      "decentralized, \"market based sybil resistant\" "
      "and IP based onion routing network");
  // clang-format off
  options.add_options()
      ("v,verbose", "Verbose", cxxopts::value<bool>())
#ifdef _WIN32
      ("install", "install win32 daemon to SCM", cxxopts::value<bool>())
      ("remove", "remove win32 daemon from SCM", cxxopts::value<bool>())
#endif
      ("h,help", "help", cxxopts::value<bool>())("version", "version", cxxopts::value<bool>())
      ("g,generate", "generate client config", cxxopts::value<bool>())
      ("r,router", "run as router instead of client", cxxopts::value<bool>())
      ("f,force", "overwrite", cxxopts::value<bool>())
      ("c,colour", "colour output", cxxopts::value<bool>()->default_value("true"))
      ("b,background", "background mode (start, but do not connect to the network)",
       cxxopts::value<bool>())
      ("config", "path to configuration file", cxxopts::value<std::string>())
      ;
  // clang-format on

  options.parse_positional("config");

  bool genconfigOnly = false;
  bool overwrite = false;
  std::optional<fs::path> configFile;
  try
  {
    auto result = options.parse(argc, argv);

    if (result.count("verbose") > 0)
    {
      SetLogLevel(llarp::eLogDebug);
      llarp::LogDebug("debug logging activated");
    }

    if (!result["colour"].as<bool>())
    {
      llarp::LogContext::Instance().logStream =
          std::make_unique<llarp::OStreamLogStream>(false, std::cerr);
    }

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

    if (result.count("background") > 0)
    {
      opts.background = true;
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
        LogError("cannot generate config at ", *configFile, ": ", ex.what());
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
        LogError("cannot check if ", *configFile, " exists: ", ex.what());
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

  std::thread main_thread{[&] { run_main_context(configFile, opts); }};
  auto ftr = exit_code.get_future();

#ifdef _WIN32
  ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
#endif

  do
  {
    // do periodic non lokinet related tasks here
    if (ctx and ctx->IsUp() and not ctx->LooksAlive())
    {
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
        LogError(wtf);
        llarp::LogContext::Instance().ImmediateFlush();
      }
#ifdef _WIN32
      TellWindowsServiceStopped();
#endif
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

  llarp::LogContext::Instance().ImmediateFlush();
  if (ctx)
  {
    ctx.reset();
  }
  return code;
}

#ifdef _WIN32
BOOL
ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
  static DWORD dwCheckPoint = 1;

  // Fill in the SERVICE_STATUS structure.
  SvcStatus.dwCurrentState = dwCurrentState;
  SvcStatus.dwWin32ExitCode = dwWin32ExitCode;
  SvcStatus.dwWaitHint = dwWaitHint;

  if (dwCurrentState == SERVICE_START_PENDING)
    SvcStatus.dwControlsAccepted = 0;
  else
    SvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
    SvcStatus.dwCheckPoint = 0;
  else
    SvcStatus.dwCheckPoint = dwCheckPoint++;

  // Report the status of the service to the SCM.
  return SetServiceStatus(SvcStatusHandle, &SvcStatus);
}

VOID FAR PASCAL
SvcCtrlHandler(DWORD dwCtrl)
{
  // Handle the requested control code.

  switch (dwCtrl)
  {
    case SERVICE_CONTROL_STOP:
      ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
      // Signal the service to stop.
      handle_signal(SIGINT);
      return;

    case SERVICE_CONTROL_INTERROGATE:
      break;

    default:
      break;
  }
}

// The win32 daemon entry point is just a trampoline that returns control
// to the original lokinet entry
// and only gets called if we get --win32-daemon in the command line
VOID FAR PASCAL
win32_daemon_entry(DWORD argc, LPTSTR* argv)
{
  // Register the handler function for the service
  SvcStatusHandle = RegisterServiceCtrlHandler("lokinet", SvcCtrlHandler);

  if (!SvcStatusHandle)
  {
    llarp::LogError("failed to register daemon control handler");
    return;
  }

  // These SERVICE_STATUS members remain as set here
  SvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  SvcStatus.dwServiceSpecificExitCode = 0;

  // Report initial status to the SCM
  ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
  // SCM clobbers startup args, regenerate them here
  argc = 2;
  argv[1] = strdup("c:/programdata/lokinet/lokinet.ini");
  argv[2] = nullptr;
  lokinet_main(argc, argv);
}
#endif
