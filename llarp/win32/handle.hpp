#pragma once

#include "exception.hpp"

namespace llarp::win32
{
    inline void ensure_handle_is_valid(HANDLE h)
    {
        BY_HANDLE_FILE_INFORMATION info{};
        if (GetFileInformationByHandle(h, &info))
            return;
        if (auto err = GetLastError())
        {
            SetLastError(0);
            throw llarp::win32::error{err, "handle validity check failed"};
        }
    }
}  // namespace llarp::win32
