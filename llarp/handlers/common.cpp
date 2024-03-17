#include "common.hpp"

#include <llarp/router/router.hpp>

namespace llarp::handlers
{
    static auto logcat = llarp::log::Cat("base_handler");

    void BaseHandler::load_key_file(std::optional<fs::path> p, Router& r)
    {
        try
        {
            if (p.has_value())
                _identity.ensure_keys(*p, r.key_manager()->needs_backup());
            else
                _identity.regenerate_keys();
        }
        catch (const std::exception& e)
        {
            auto err = "API endpoint keyfile failed to load: {}"_format(e.what());
            log::error(logcat, "{}", err);
            throw std::runtime_error{err};
        }
    }

    const std::shared_ptr<EventLoop>& BaseHandler::loop() const
    {
        return _router.loop();
    }
}  // namespace llarp::handlers
