#include "interface_info.hpp"

namespace llarp::net
{
    std::string InterfaceInfo::to_string() const
    {
        return fmt::format("{}[i={}; addrs={}]", name, index, fmt::join(addrs, ","));
    }
}  // namespace llarp::net
