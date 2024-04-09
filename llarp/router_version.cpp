#include "router_version.hpp"

#include "util/buffer.hpp"
#include "util/logging.hpp"

#include <oxenc/bt.h>

#include <cassert>

namespace llarp
{
    static auto logcat = llarp::log::Cat("router_version");

    RouterVersion::RouterVersion(const std::array<uint16_t, 3>& router, uint64_t proto)
        : _version(router), _proto(proto)
    {}

    bool RouterVersion::is_compatible_with(const RouterVersion& other) const
    {
        return _proto == other._proto;
    }

    std::string RouterVersion::bt_encode() const
    {
        oxenc::bt_list_producer btlp;

        try
        {
            btlp.append(_proto);

            for (auto& v : _version)
                btlp.append(v);
        }
        catch (...)
        {
            log::critical(logcat, "Error: RouterVersion failed to bt encode contents!");
        }

        return std::move(btlp).str();
    }

    void RouterVersion::clear()
    {
        _version.fill(0);
        _proto = INVALID_VERSION;
        assert(is_empty());
    }

    bool RouterVersion::is_empty() const
    {
        return *this == emptyRouterVersion;
    }

    bool RouterVersion::bt_decode(std::string_view buf)
    {
        // clear before hand
        clear();

        try
        {
            oxenc::bt_list_consumer btlc{buf};

            _proto = btlc.consume_integer<int64_t>();

            // The previous bt_decode implementation accepted either a full or empty version array,
            // so accounting for this with the following check...
            if (not btlc.is_finished())
            {
                for (auto& v : _version)
                    v = btlc.consume_integer<uint16_t>();
            }
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "RouterVersion parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }

        return true;
    }

    std::string RouterVersion::to_string() const
    {
        return std::to_string(_version.at(0)) + "." + std::to_string(_version.at(1)) + "."
            + std::to_string(_version.at(2)) + " protocol version " + std::to_string(_proto);
    }

}  // namespace llarp
