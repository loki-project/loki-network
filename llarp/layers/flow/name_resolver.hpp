#pragma once

#include "flow_addr.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <optional>

#include <oxenc/variant.h>

#include <llarp/util/types.hpp>
#include <llarp/dns/question.hpp>
#include <string_view>
#include <variant>
#include <vector>

namespace llarp::layers::flow
{

  class NameCache;
  class FlowLayer;

  class NameResolver
  {
    NameCache& _name_cache;
    FlowLayer& _parent;

   public:
    NameResolver(const NameResolver&) = delete;
    NameResolver(NameResolver&&) = delete;
    NameResolver(NameCache& name_cache, FlowLayer& parent);

    /// resolve name using in network resolution
    void
    resolve_flow_addr_async(std::string name, std::function<void(std::optional<FlowAddr>)> handler);

    /// return true if this looks like a name we can resolve.
    static bool
    name_well_formed(std::string_view name);
  };

}  // namespace llarp::layers::flow
