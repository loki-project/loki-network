#include "session.hpp"

namespace llarp::service
{
    nlohmann::json Session::ExtractStatus() const
    {
        nlohmann::json obj{
            {"lastSend", to_json(lastSend)},
            {"lastRecv", to_json(lastRecv)},
            {"replyIntro", replyIntro.ExtractStatus()},
            // {"remote", Addr().to_string()},
            {"seqno", seqno},
            {"tx", messagesSend},
            {"rx", messagesRecv},
            {"intro", intro.ExtractStatus()}};
        return obj;
    }

    // Address Session::Addr() const
    // {
    //     return remote.address();
    // }

    bool Session::IsExpired(std::chrono::milliseconds now, std::chrono::milliseconds lifetime) const
    {
        if (forever)
            return false;
        const auto lastUsed = std::max(lastSend, lastRecv);
        if (lastUsed == 0s)
            return intro.is_expired(now);
        return now >= lastUsed && (now - lastUsed > lifetime);
    }

    void Session::TX()
    {
        messagesSend++;
        lastSend = time_now_ms();
    }

    void Session::RX()
    {
        messagesRecv++;
        lastRecv = time_now_ms();
    }

}  // namespace llarp::service
