#include "dll.hpp"

#include <llarp/util/logging.hpp>
#include <llarp/util/str.hpp>

namespace llarp::win32
{
    namespace
    {
        auto cat = log::Cat("win32-dll");
    }

    namespace detail
    {
        HMODULE
        load_dll(const std::string& dll)
        {
            auto handle = LoadLibraryExA(dll.c_str(), NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
            if (not handle)
                throw win32::error{fmt::format("failed to load '{}'", dll)};
            log::info(cat, "loaded '{}'", dll);
            return handle;
        }
    }  // namespace detail
}  // namespace llarp::win32
