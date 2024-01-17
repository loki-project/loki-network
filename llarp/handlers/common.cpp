#include "common.hpp"

#include <llarp/router/router.hpp>

namespace llarp::handlers
{
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
            log::error(logcat, err);
            throw std::runtime_error{err};
        }
    }
}  // namespace llarp::handlers
