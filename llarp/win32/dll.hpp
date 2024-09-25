#pragma once
#include "exception.hpp"

#include <llarp/util/str.hpp>

#include <windows.h>

namespace llarp::win32
{
    namespace detail
    {
        HMODULE
        load_dll(const std::string& dll);

        template <typename Func, typename... More>
        void load_funcs(HMODULE handle, const std::string& name, Func*& f, More&&... more)
        {
            if (auto ptr = GetProcAddress(handle, name.c_str()))
                f = reinterpret_cast<Func*>(ptr);
            else
                throw win32::error{fmt::format("function '{}' not found", name)};
            if constexpr (sizeof...(More) > 0)
                load_funcs(handle, std::forward<More>(more)...);
        }
    }  // namespace detail

    // Loads a DLL and extracts function pointers from it.  Takes the dll name and pairs of
    // name/function pointer arguments.  Throws on failure.
    template <typename Func, typename... More>
    void load_dll_functions(const std::string& dll, const std::string& fname, Func*& f, More&&... funcs)
    {
        detail::load_funcs(detail::load_dll(dll), fname, f, std::forward<More>(funcs)...);
    }
}  // namespace llarp::win32
