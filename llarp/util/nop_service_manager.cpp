#include "service_manager.hpp"

namespace llarp::sys
{
    NOP_SystemLayerHandler _manager{};
    I_SystemLayerManager* const service_manager = &_manager;
}  // namespace llarp::sys
