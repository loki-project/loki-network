#pragma once

#include <llarp/crypto/crypto.hpp>

#include <windows.h>

#include <type_traits>

namespace llarp::win32
{
    /// @brief given a container of data hash it and make it into a GUID so we have a way to
    /// deterministically generate GUIDs
    template <typename Data>
    inline GUID MakeDeterministicGUID(Data data)
    {
        ShortHash h{};
        auto hash = [&h](uint8_t* d, size_t size) { crypto::shorthash(h, d, size); };

        if constexpr (std::is_same_v<Data, std::string>)
            hash(reinterpret_cast<uint8_t*>(data.data()), data.size());
        else
        {
            auto dat = llarp_buffer_t{data};
            hash(dat.base, dat.sz);
        }
        GUID guid{};
        std::copy_n(h.begin(), std::min(sizeof(GUID), sizeof(ShortHash)), reinterpret_cast<uint8_t*>(&guid));
        return guid;
    }
}  // namespace llarp::win32
