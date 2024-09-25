#include <llarp.hpp>
#include <llarp/router/router.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/service_manager.hpp>

#include <systemd/sd-daemon.h>

#include <cassert>

namespace llarp::sys
{
    class SD_Manager : public I_SystemLayerManager
    {
        llarp::sys::ServiceState m_State{ServiceState::Initial};

      public:
        /// change our state and report it to the system layer
        void we_changed_our_state(ServiceState st) override
        {
            m_State = st;
            report_changed_state();
        }

        void report_changed_state() override
        {
            if (m_State == ServiceState::Running)
            {
                ::sd_notify(0, "READY=1");
                return;
            }
            if (m_State == ServiceState::Stopping)
            {
                ::sd_notify(0, "STOPPING=1");
                return;
            }
        }

        void report_periodic_stats() override
        {
            if (m_Context and m_Context->router and not m_disable)
            {
                auto status = fmt::format("WATCHDOG=1\nSTATUS={}", m_Context->router->status_line());
                ::sd_notify(0, status.c_str());
            }
        }

        void system_changed_our_state(ServiceState) override
        {
            // not applicable on systemd
        }
    };

    SD_Manager _manager{};
    I_SystemLayerManager* const service_manager = &_manager;

}  // namespace llarp::sys
