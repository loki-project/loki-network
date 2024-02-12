#include <llarp.hpp>
#include <llarp/config/config.hpp>  // for ensure_config
// #include <llarp/constants/files.hpp>
#include <llarp/constants/platform.hpp>
#include <llarp/constants/version.hpp>
#include <llarp/ev/ev.hpp>
#include <llarp/ev/loop.hpp>
#include <llarp/util/exceptions.hpp>
// #include <llarp/util/logging.hpp>
#include <llarp/util/lokinet_init.h>
#include <llarp/util/thread/threading.hpp>

#include <CLI/CLI.hpp>
#include <fmt/core.h>
#include <oxen/log.hpp>

#include <csignal>
// #include <cstdlib>
// #include <iostream>
#include <memory>
// #include <optional>
#include <stdexcept>
// #include <string>
#include <thread>
// #include <utility>

#ifdef _WIN32
#include <llarp/win32/service_manager.hpp>
#else
#include <llarp/util/service_manager.hpp>
#endif

namespace
{
    struct command_line_options
    {
        // bool options
        bool help = false;
        bool version = false;
        bool generate = false;
        bool router = false;
        bool config = false;
        bool configOnly = false;
        bool overwrite = false;

        // string options
        // TODO: change this to use a std::filesystem::path once we stop using ghc::filesystem on
        // some platforms
        std::string configPath;

        // windows options
        bool win_install = false;
        bool win_remove = false;
    };

    // windows-specific function declarations
    int startWinsock();
    void install_win32_daemon();
    void uninstall_win32_daemon();

    // operational function definitions
    int lokinet_main(int, char**);
    void handle_signal(int sig);
    static void run_main_context(std::optional<fs::path> confFile, const llarp::RuntimeOptions opts);

    // variable declarations
    static auto logcat = llarp::log::Cat("main");
    std::shared_ptr<llarp::Context> ctx;
    std::promise<int> exit_code;

    // operational function definitions
    void handle_signal(int sig)
    {
        llarp::log::info(logcat, "Handling signal {}", sig);

        if (ctx)
            ctx->_loop->call([sig]() { ctx->handle_signal(sig); });
        else
            std::cerr << "Received signal " << sig << ", but have no context yet. Ignoring!" << std::endl;
    }

    // Windows specific code
#ifdef _WIN32
    extern "C" LONG FAR PASCAL win32_signal_handler(EXCEPTION_POINTERS*);
    extern "C" VOID FAR PASCAL win32_daemon_entry(DWORD, LPTSTR*);
    VOID insert_description();

    extern "C" BOOL FAR PASCAL handle_signal_win32(DWORD fdwCtrlType)
    {
        UNREFERENCED_PARAMETER(fdwCtrlType);
        handle_signal(SIGINT);
        return TRUE;  // probably unreachable
    };

    int startWinsock()
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

    void install_win32_daemon()
    {
        SC_HANDLE schSCManager;
        SC_HANDLE schService;
        std::array<char, 1024> szPath{};

        if (!GetModuleFileName(nullptr, szPath.data(), MAX_PATH))
        {
            llarp::log::error(logcat, "Cannot install service {}", GetLastError());
            return;
        }

        // Get a handle to the SCM database.
        schSCManager = OpenSCManager(
            nullptr,                 // local computer
            nullptr,                 // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

        if (nullptr == schSCManager)
        {
            llarp::log::error(logcat, "OpenSCManager failed {}", GetLastError());
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
            llarp::log::error(logcat, "CreateService failed {}", GetLastError());
            CloseServiceHandle(schSCManager);
            return;
        }
        else
            llarp::log::info(logcat, "Service installed successfully");

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        insert_description();
    }

    VOID insert_description()
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
            llarp::log::error(logcat, "OpenSCManager failed {}", GetLastError());
            return;
        }

        // Get a handle to the service.
        schService = OpenService(
            schSCManager,            // SCM database
            "lokinet",               // name of service
            SERVICE_CHANGE_CONFIG);  // need change config access

        if (schService == nullptr)
        {
            llarp::log::error(logcat, "OpenService failed {}", GetLastError());
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
            llarp::log::error(logcat, "ChangeServiceConfig2 failed");
        }
        else
            llarp::log::info(log_cat, "Service description updated successfully.");

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }

    void uninstall_win32_daemon()
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
            llarp::log::error(logcat, "OpenSCManager failed {}", GetLastError());
            return;
        }

        // Get a handle to the service.
        schService = OpenService(
            schSCManager,  // SCM database
            "lokinet",     // name of service
            0x10000);      // need delete access

        if (schService == nullptr)
        {
            llarp::log::error(logcat, "OpenService failed {}", GetLastError());
            CloseServiceHandle(schSCManager);
            return;
        }

        // Delete the service.
        if (!DeleteService(schService))
        {
            llarp::log::error(logcat, "DeleteService failed {}", GetLastError());
        }
        else
            llarp::log::info(logcat, "Service deleted successfully");

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }

    /// minidump generation for windows jizz
    /// will make a coredump when there is an unhandled exception
    LONG GenerateDump(EXCEPTION_POINTERS* pExceptionPointers)
    {
        const auto flags =
            (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithThreadInfo);

        const std::string fname = fmt::format("C:\\ProgramData\\lokinet\\crash-{}.dump", llarp::time_now_ms().count());

        HANDLE hDumpFile;
        SYSTEMTIME stLocalTime;
        GetLocalTime(&stLocalTime);
        MINIDUMP_EXCEPTION_INFORMATION ExpParam{};

        hDumpFile = CreateFile(
            fname.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);

        ExpParam.ExceptionPointers = pExceptionPointers;
        ExpParam.ClientPointers = TRUE;

        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile, flags, &ExpParam, NULL, NULL);

        return 1;
    }

    VOID FAR PASCAL SvcCtrlHandler(DWORD dwCtrl)
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

    // The win32 daemon entry point is where we go when invoked as a windows service; we do the
    // required service dance and then pretend we were invoked via main().
    VOID FAR PASCAL win32_daemon_entry(DWORD, LPTSTR* argv)
    {
        // Register the handler function for the service
        auto* svc = dynamic_cast<llarp::sys::SVC_Manager*>(llarp::sys::service_manager);
        svc->handle = RegisterServiceCtrlHandler("lokinet", SvcCtrlHandler);

        if (svc->handle == nullptr)
        {
            llarp::log::error(logcat, "failed to register daemon control handler");
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

    int lokinet_main(int argc, char** argv)
    {
        llarp::RuntimeOptions opts;
        opts.showBanner = false;

#ifdef _WIN32
        if (startWinsock())
            return -1;
        SetConsoleCtrlHandler(handle_signal_win32, TRUE);
#endif

        CLI::App cli{
            "LokiNET is a free, open source, private, decentralized, market-based sybil resistant "
            "and "
            "IP "
            "based onion routing network",
            "lokinet"};
        command_line_options options{};

        // flags: boolean values in command_line_options struct
        cli.add_flag("--version", options.version, "Lokinet version");
        cli.add_flag("-g,--generate", options.generate, "Generate default configuration and exit");
        cli.add_flag("-r,--router", options.router, "Run lokinet in routing mode instead of client-only mode");
        cli.add_flag("-f,--force", options.overwrite, "Force writing config even if file exists");

        // options: string
        cli.add_option("config,--config", options.configPath, "Path to lokinet.ini configuration file")
            ->capture_default_str();

        if constexpr (llarp::platform::is_windows)
        {
            cli.add_flag("--install", options.win_install, "Install win32 daemon to SCM");
            cli.add_flag("--remove", options.win_remove, "Remove win32 daemon from SCM");
        }

        try
        {
            cli.parse(argc, argv);
        }
        catch (const CLI::ParseError& e)
        {
            return cli.exit(e);
        }

        std::optional<fs::path> configFile;

        try
        {
            if (options.version)
            {
                std::cout << llarp::LOKINET_VERSION_FULL << std::endl;
                return 0;
            }

            if constexpr (llarp::platform::is_windows)
            {
                if (options.win_install)
                {
                    install_win32_daemon();
                    return 0;
                }
                if (options.win_remove)
                {
                    uninstall_win32_daemon();
                    return 0;
                }
            }

            opts.isSNode = options.router;

            if (options.generate)
            {
                options.configOnly = true;
            }

            if (not options.configPath.empty())
            {
                configFile = options.configPath;
            }
        }
        catch (const CLI::OptionNotFound& e)
        {
            cli.exit(e);
        }
        catch (const CLI::Error& e)
        {
            cli.exit(e);
        };

        if (configFile.has_value())
        {
            // when we have an explicit filepath
            fs::path basedir = configFile->parent_path();
            if (options.configOnly)
            {
                try
                {
                    llarp::ensure_config(basedir, *configFile, options.overwrite, opts.isSNode);
                }
                catch (std::exception& ex)
                {
                    llarp::log::error(logcat, "cannot generate config at {}: {}", *configFile, ex.what());
                    return 1;
                }
            }
            else
            {
                try
                {
                    if (!fs::exists(*configFile))
                    {
                        llarp::log::error(logcat, "Config file not found {}", *configFile);
                        return 1;
                    }
                }
                catch (std::exception& ex)
                {
                    llarp::log::error(logcat, "cannot check if ", *configFile, " exists: ", ex.what());
                    return 1;
                }
            }
        }
        else
        {
            try
            {
                llarp::ensure_config(
                    llarp::GetDefaultDataDir(), llarp::GetDefaultConfigPath(), options.overwrite, opts.isSNode);
            }
            catch (std::exception& ex)
            {
                llarp::log::error(logcat, "cannot ensure config: {}", ex.what());
                return 1;
            }
            configFile = llarp::GetDefaultConfigPath();
        }

        if (options.configOnly)
            return 0;

#ifdef _WIN32
        SetUnhandledExceptionFilter(&GenerateDump);
#endif

        std::thread main_thread{[configFile, opts] { run_main_context(configFile, opts); }};
        auto ftr = exit_code.get_future();

        do
        {
            // do periodic non lokinet related tasks here
            if (ctx and ctx->is_up() and not ctx->looks_alive())
            {
                auto deadlock_cat = llarp::log::Cat("deadlock");
                llarp::log::critical(deadlock_cat, "Router is deadlocked!");
                llarp::log::flush();
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

    // this sets up, configures and runs the main context
    static void run_main_context(std::optional<fs::path> confFile, const llarp::RuntimeOptions opts)
    {
        llarp::log::info(logcat, "starting up {}", llarp::LOKINET_VERSION_FULL);
        try
        {
            std::shared_ptr<llarp::Config> conf;
            if (confFile)
            {
                llarp::log::info(logcat, "Using config file: {}", *confFile);
                conf = std::make_shared<llarp::Config>(confFile->parent_path());
            }
            else
            {
                conf = std::make_shared<llarp::Config>(llarp::GetDefaultDataDir());
            }
            if (not conf->load(confFile, opts.isSNode))
            {
                llarp::log::error(logcat, "failed to parse configuration");
                exit_code.set_value(1);
                return;
            }

            // change cwd to dataDir to support relative paths in config
            fs::current_path(conf->router.data_dir);

            ctx = std::make_shared<llarp::Context>();
            ctx->configure(std::move(conf));

            signal(SIGINT, handle_signal);
            signal(SIGTERM, handle_signal);

#ifndef _WIN32
            signal(SIGHUP, handle_signal);
            signal(SIGUSR1, handle_signal);
#endif

            try
            {
                ctx->setup(opts);
            }
            catch (llarp::util::bind_socket_error& ex)
            {
                llarp::log::error(logcat, "{}; is lokinet already running?", ex.what());
                exit_code.set_value(1);
                return;
            }
            catch (const std::exception& ex)
            {
                llarp::log::error(logcat, "failed to start up lokinet: {}", ex.what());
                exit_code.set_value(1);
                return;
            }
            llarp::util::SetThreadName("llarp-mainloop");

            auto result = ctx->run(opts);
            exit_code.set_value(result);
        }
        catch (const std::exception& e)
        {
            llarp::log::error(logcat, "Fatal: caught exception while running: {}", e.what());
            exit_code.set_exception(std::current_exception());
        }
        catch (...)
        {
            llarp::log::error(logcat, "Fatal: caught non-standard exception while running");
            exit_code.set_exception(std::current_exception());
        }
    }

}  // namespace

int main(int argc, char* argv[])
{
    // Set up a default, stderr logging for very early logging; we'll replace this later once we
    // read the desired log info from config.
    llarp::log::add_sink(llarp::log::Type::Print, "stderr");
    llarp::log::reset_level(llarp::log::Level::info);

    llarp::logRingBuffer = std::make_shared<llarp::log::RingBufferSink>(100);
    llarp::log::add_sink(llarp::logRingBuffer, llarp::log::DEFAULT_PATTERN_MONO);

#ifndef _WIN32
    return lokinet_main(argc, argv);
#else
    if (auto hntdll = GetModuleHandle("ntdll.dll"))
    {
        if (GetProcAddress(hntdll, "wine_get_version"))
        {
            static const char* text = "Don't run lokinet in wine, aborting startup";
            static const char* title = "Lokinet Wine Error";
            MessageBoxA(NULL, text, title, MB_ICONHAND);
            std::abort();
        }
    }

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
        llarp::log::critical(logcat, "Error launching service: {}", std::system_category().message(error));
        return 1;
    }
#endif
}
