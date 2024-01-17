#include "session.hpp"

namespace llarp::service
{
    StatusObject Session::ExtractStatus() const
    {
        StatusObject obj{
            {"lastSend", to_json(lastSend)},
            {"lastRecv", to_json(lastRecv)},
            {"replyIntro", replyIntro.ExtractStatus()},
            {"remote", Addr().ToString()},
            {"seqno", seqno},
            {"tx", messagesSend},
            {"rx", messagesRecv},
            {"intro", intro.ExtractStatus()}};
        return obj;
    }

    Address Session::Addr() const
    {
        return remote.Addr();
    }

    bool Session::IsExpired(llarp_time_t now, llarp_time_t lifetime) const
    {
        if (forever)
            return false;
        const auto lastUsed = std::max(lastSend, lastRecv);
        if (lastUsed == 0s)
            return intro.IsExpired(now);
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
