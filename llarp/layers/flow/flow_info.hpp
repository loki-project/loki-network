#pragma once

#include "flow_addr.hpp"
#include "flow_tag.hpp"
#include "flow_constants.hpp"

#include <llarp/service/convotag.hpp>

namespace llarp::layers::flow
{

  /// in lokinet our onion routed flows are comprised of a source and destination flow layer
  /// address, a flow tag (an identifier to mark a distinct flow), and a pivot that each is using in
  /// common which acts as our analog to an ipv6 flow label, see rfc6437.
  struct FlowInfo
  {
    /// source and destination addresses we associate with this flow.
    FlowAddr src, dst;

    /// cleartext identifier used on outer framing of the traffic. lets us tell what is from who.
    FlowTag tag;

    /// mtu between src and dst.
    uint16_t mtu{default_flow_mtu};

    std::string
    ToString() const;

    service::ConvoTag
    convo_tag() const;

    bool
    operator==(const FlowInfo& other) const;
  };
}  // namespace llarp::layers::flow

namespace llarp
{
  template <>
  inline constexpr bool IsToStringFormattable<llarp::layers::flow::FlowInfo> = true;

}

namespace std
{
  template <>
  struct hash<llarp::layers::flow::FlowInfo>
  {
    size_t
    operator()(const llarp::layers::flow::FlowInfo& info) const
    {
      return std::hash<llarp::layers::flow::FlowAddr>{}(info.src)
          ^ (std::hash<llarp::layers::flow::FlowAddr>{}(info.dst) << 3)
          ^ (std::hash<llarp::layers::flow::FlowTag>{}(info.tag) << 5);
    }
  };
}  // namespace std
