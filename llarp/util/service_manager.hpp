#pragma once

namespace llarp
{
    struct Context;
}

namespace llarp::sys
{

    // what state lokinet will report we are in to the system layer
    enum class ServiceState
    {
        Initial,
        Starting,
        Running,
        Stopping,
        Stopped,
        HardStop,
        Failed,
    };

    /// interface type for interacting with the os dependant system layer
    class I_SystemLayerManager
    {
      protected:
        bool m_disable{false};
        llarp::Context* m_Context{nullptr};

        /// change our state and report it to the system layer
        virtual void we_changed_our_state(ServiceState st) = 0;

      public:
        virtual ~I_SystemLayerManager() = default;

        /// disable all reporting to system layer
        inline void disable()
        {
            m_disable = true;
        }

        /// give our current lokinet context to the system layer manager
        inline void give_context(llarp::Context* ctx)
        {
            m_Context = ctx;
        }

        /// system told us to enter this state
        virtual void system_changed_our_state(ServiceState st) = 0;

        /// report our current state to the system layer
        virtual void report_changed_state() = 0;

        /// report our stats on each timer tick
        virtual void report_periodic_stats(){};

        void starting()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Starting);
        }

        void ready()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Running);
        }

        void stopping()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Stopping);
        }

        void stopped()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Stopped);
        }

        void failed()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Failed);
        }
    };

    extern I_SystemLayerManager* const service_manager;

    class NOP_SystemLayerHandler : public I_SystemLayerManager
    {
      protected:
        void we_changed_our_state(ServiceState) override
        {}

      public:
        void report_changed_state() override{};
        void system_changed_our_state(ServiceState) override{};
    };
}  // namespace llarp::sys
