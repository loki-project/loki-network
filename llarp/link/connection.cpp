#include "connection.hpp"

namespace llarp::link
{
    static auto logcat = llarp::log::Cat("link_conn");

    Connection::Connection(
        std::shared_ptr<oxen::quic::connection_interface> c,
        std::shared_ptr<oxen::quic::BTRequestStream> s,
        bool is_relay)
        : conn{std::move(c)}, control_stream{std::move(s)}, remote_is_relay{is_relay}
    {}

    void Connection::close_quietly()
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);
        conn->set_close_quietly();
        conn->close_connection();
    }
}  // namespace llarp::link
