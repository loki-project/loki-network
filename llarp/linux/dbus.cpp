#ifdef WITH_SYSTEMD
#include "dbus.hpp"

namespace llarp::linux
{
    system_bus_exception::system_bus_exception(int err)
        : std::runtime_error{"cannot connect to system bus: " + std::string{strerror(-err)}}
    {}

    dbus_call_exception::dbus_call_exception(std::string meth, int err)
        : std::runtime_error{"failed to call dbus function '" + meth + "': " + std::string{strerror(-err)}}
    {}

    DBUS::DBUS(std::string _interface, std::string _instance, std::string _call)
        : m_interface{std::move(_interface)}, m_instance{std::move(_instance)}, m_call{std::move(_call)}
    {
        sd_bus* bus{nullptr};
        if (auto err = sd_bus_open_system(&bus); err < 0)
            throw system_bus_exception{err};
        m_ptr.reset(bus);
    }
}  // namespace llarp::linux
#endif
