#include "connection.hpp"

namespace llarp::link
{
    Connection::Connection(
        std::shared_ptr<oxen::quic::connection_interface> c,
        std::shared_ptr<oxen::quic::BTRequestStream> s,
        bool is_relay)
        : conn{std::move(c)}, control_stream{std::move(s)}, remote_is_relay{is_relay}
    {}
}  // namespace llarp::link
