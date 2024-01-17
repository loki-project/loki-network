#include "endpoint_state.hpp"

namespace llarp::service
{
    StatusObject EndpointState::ExtractStatus(StatusObject& obj) const
    {
        obj["lastPublished"] = to_json(last_publish);
        obj["lastPublishAttempt"] = to_json(last_publish_attempt);
        obj["introset"] = local_introset.ExtractStatus();
        // static auto getSecond = [](const auto& item) -> auto
        // {
        //   return item.second.ExtractStatus();
        // };

        // std::transform(
        //     dead_sessions.begin(),
        //     dead_sessions.end(),
        //     std::back_inserter(obj["deadSessions"]),
        //     getSecond);
        // std::transform(
        //     remote_sessions.begin(),
        //     remote_sessions.end(),
        //     std::back_inserter(obj["remoteSessions"]),
        //     getSecond);
        // std::transform(
        //     snode_sessions.begin(),
        //     snode_sessions.end(),
        //     std::back_inserter(obj["snodeSessions"]),
        //     [](const auto& item) { return item.second->ExtractStatus(); });

        StatusObject sessionObj{};

        // TODO:
        // for (const auto& item : m_Sessions)
        // {
        //   std::string k = item.first.ToHex();
        //   sessionObj[k] = item.second.ExtractStatus();
        // }

        obj["converstations"] = sessionObj;
        return obj;
    }
}  // namespace llarp::service
