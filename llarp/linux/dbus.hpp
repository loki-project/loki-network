#pragma once

extern "C"
{
#include <systemd/sd-bus.h>
}
#include <memory>
#include <stdexcept>
#include <string>

namespace llarp::linux
{
    /// exception for connecting to system bus
    class system_bus_exception : public std::runtime_error
    {
      public:
        explicit system_bus_exception(int err);
    };

    /// exception for a failed calling of a dbus method
    class dbus_call_exception : public std::runtime_error
    {
      public:
        explicit dbus_call_exception(std::string meth, int err);
    };

    class DBUS
    {
        struct sd_bus_deleter
        {
            void operator()(sd_bus* ptr) const { sd_bus_unref(ptr); }
        };
        std::unique_ptr<sd_bus, sd_bus_deleter> m_ptr;
        const std::string m_interface;
        const std::string m_instance;
        const std::string m_call;

      public:
        DBUS(std::string _interface, std::string _instance, std::string _call);

        template <typename... T>
        void operator()(std::string method, const char* arg_format, T... args)
        {
            sd_bus_error error = SD_BUS_ERROR_NULL;
            sd_bus_message* msg = nullptr;
            auto r = sd_bus_call_method(
                m_ptr.get(),
                m_interface.c_str(),
                m_instance.c_str(),
                m_call.c_str(),
                method.c_str(),
                &error,
                &msg,
                arg_format,
                args...);

            if (r < 0)
                throw dbus_call_exception{std::move(method), r};

            sd_bus_message_unref(msg);
            sd_bus_error_free(&error);
        }
    };
}  // namespace llarp::linux
