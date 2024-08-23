#include "constants/version.hpp"
#include "crypto/crypto.hpp"
#include "net/net.hpp"
#include "router_contact.hpp"
#include "util/buffer.hpp"
#include "util/file.hpp"
#include "util/time.hpp"

#include <oxenc/bt_serialize.h>

namespace llarp
{
    static auto logcat = log::Cat("RC");

    RemoteRC::RemoteRC(oxenc::bt_dict_consumer btdc)
    {
        try
        {
            bt_load(btdc);
            bt_verify(btdc, /*reject_expired=*/true);
        }
        catch (const std::exception& e)
        {
            auto err = "Exception caught parsing RemoteRC: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }
    }

    bool RemoteRC::read(const fs::path& fname)
    {
        _payload.resize(MAX_RC_SIZE);

        try
        {
            auto nread = util::file_to_buffer(fname, _payload.data(), _payload.size());
            log::trace(logcat, "{}B read from file (path:{})!", nread, fname);
            _payload.resize(nread);

            oxenc::bt_dict_consumer btdc{_payload};
            bt_load(btdc);
            bt_verify(btdc);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Failed to read or validate RC from {}: {}", fname, e.what());
            return false;
        }

        return true;
    }

    bool RemoteRC::verify() const
    {
        oxenc::bt_dict_consumer btdc{_payload};
        bt_verify(btdc);
        return true;
    }

}  // namespace llarp
