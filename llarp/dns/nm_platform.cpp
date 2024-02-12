#include "nm_platform.hpp"
#ifdef WITH_SYSTEMD

extern "C"
{
#include <net/if.h>
}

#include <llarp/linux/dbus.hpp>

using namespace std::literals;

namespace llarp::dns::nm
{
    void Platform::set_resolver(unsigned int, oxen::quic::Address, bool)
    {
        // todo: implement me eventually
    }
}  // namespace llarp::dns::nm
#endif
