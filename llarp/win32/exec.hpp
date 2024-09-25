#pragma once

#include <llarp/util/time.hpp>

#include <windows.h>

#include <string>

namespace llarp::win32
{
    /// RAII wrapper for calling a subprocess in win32 for parallel executuion in the same scope
    /// destructor blocks until timeout has been hit of the execution of the subprocses finished
    class OneShotExec
    {
        STARTUPINFO _si;
        PROCESS_INFORMATION _pi;
        const DWORD _timeout;

        OneShotExec(std::string cmd, std::chrono::milliseconds timeout);

      public:
        /// construct a call to an exe in system32 with args, will resolve the full path of the exe
        /// to prevent path injection
        explicit OneShotExec(std::string exe, std::string args, std::chrono::milliseconds timeout = 5s);

        ~OneShotExec();
    };

    /// a wrapper for OneShotExec that calls the thing we want on destruction
    class DeferExec
    {
        std::string _exe;
        std::string _args;
        std::chrono::milliseconds _timeout;

      public:
        explicit DeferExec(std::string exe, std::string args, std::chrono::milliseconds timeout = 5s)
            : _exe{std::move(exe)}, _args{std::move(args)}, _timeout{std::move(timeout)}
        {}

        ~DeferExec();
    };

    /// simple wrapper to run a single command in a blocking way
    void Exec(std::string exe, std::string args);

}  // namespace llarp::win32
