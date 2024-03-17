#pragma once
#include <llarp/util/service_manager.hpp>
#include <llarp/util/types.hpp>

#include <windows.h>

#include <dbghelp.h>

#include <chrono>

namespace llarp::sys
{

    class SVC_Manager : public I_SystemLayerManager
    {
        SERVICE_STATUS _status;

      public:
        SERVICE_STATUS_HANDLE handle;

        // How long we tell Windows to give us to startup before assuming we have stalled/hung.  The
        // biggest potential time here is wintun, which if it is going to fail appears to take
        // around 15s before doing so.
        static constexpr auto StartupTimeout = 17s;

        // How long we tell Windows to give us to fully stop before killing us.
        static constexpr auto StopTimeout = 5s;

        SVC_Manager();

        void system_changed_our_state(ServiceState st) override;

        void report_changed_state() override;

        void we_changed_our_state(ServiceState st) override;
    };
}  // namespace llarp::sys
