#include "exception.hpp"

#include "windows.h"

#include <llarp/util/str.hpp>

#include <array>

namespace llarp::win32

{
    error::error(std::string msg) : error{GetLastError(), std::move(msg)} {}
    error::error(DWORD err, std::string msg)
        : std::runtime_error{fmt::format("{}: {} (code={})", msg, error_to_string(err), err)}
    {}
    std::string error_to_string(DWORD err)
    {
        // mostly yoinked from https://stackoverflow.com/a/45565001
        LPTSTR psz{nullptr};
        const DWORD cchMsg = FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            nullptr,
            err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPTSTR>(&psz),
            0,
            nullptr);

        if (cchMsg <= 0)
        {
            // cannot get message for error, reset the last error here so it does not propagate
            ::SetLastError(0);
            return "unknown error";
        }

        auto deleter = [](void* p) { ::LocalFree(p); };
        std::unique_ptr<TCHAR, decltype(deleter)> ptrBuffer{psz, deleter};
        return std::string{ptrBuffer.get(), cchMsg};
    }
}  // namespace llarp::win32
