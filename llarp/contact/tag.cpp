#include "tag.hpp"

#include <llarp/net/policy.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp
{
    static auto logcat = log::Cat("session-tag");

    session_tag::session_tag(uint8_t protocol)
    {
        randombytes(buf.data(), SIZE);
        std::memcpy(buf.data(), &protocol, sizeof(uint8_t));
        log::debug(logcat, "new session tag generated: {}", buffer_printer{buf});
    }

    session_tag session_tag::make(uint8_t protocol) { return session_tag{protocol}; }

    std::tuple<bool, bool> session_tag::proto_bits() const
    {
        auto& p = buf[0];
        return {p & meta::to_underlying(protocol_flag::EXIT), p & meta::to_underlying(protocol_flag::TCP2QUIC)};
    }

    void session_tag::read(std::string_view data)
    {
        if (data.size() != SIZE)
            throw std::invalid_argument{
                "Buffer size mismatch (received: {}, expected: {}) reading in session tag!"_format(data.size(), SIZE)};

        std::memcpy(buf.data(), data.data(), data.size());
    }

    std::string_view session_tag::view() const { return {reinterpret_cast<const char*>(buf.data()), buf.size()}; }

    uspan session_tag::span() const { return buf; }

    std::string session_tag::to_string() const { return oxenc::to_hex(buf.begin(), buf.end()); }
}  // namespace llarp
