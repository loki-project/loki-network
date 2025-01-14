#include "relay_contact.hpp"

#include <oxenc/bt_serialize.h>

namespace llarp
{
    static auto logcat = log::Cat("relay-contact");

    RemoteRC::RemoteRC(oxenc::bt_dict_consumer btdc, bool accept_expired)
    {
        try
        {
            bt_load(btdc);
            bt_verify(btdc, not accept_expired);
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
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        _payload.resize(MAX_RC_SIZE);

        try
        {
            auto nread = util::file_to_buffer(fname, _payload.data(), _payload.size());
            log::trace(logcat, "{}B read from file (path:{})!", nread, fname);
            _payload.resize(nread);

            oxenc::bt_dict_consumer btdc{ustring_view{_payload}};
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
        oxenc::bt_dict_consumer btdc{ustring_view{_payload}};
        bt_verify(btdc);
        return true;
    }

}  // namespace llarp
