#include "interface_info.hpp"

namespace llarp::net
{
    std::string InterfaceInfo::to_string() const
    {
        return fmt::format(
            "{}[i={}; addrs={}; gw={}]",
            name,
            index,
            fmt::join(addrs, ","),
            gateway ? net::to_string(*gateway) : "none");
    }
}  // namespace llarp::net
