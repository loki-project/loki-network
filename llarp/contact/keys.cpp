#include "keys.hpp"

#include <oxenc/base32z.h>
#include <oxenc/hex.h>

namespace llarp
{
    bool PubKey::from_hex(const std::string& str)
    {
        if (str.size() != 2 * size())
            return false;
        oxenc::from_hex(str.begin(), str.end(), begin());
        return true;
    }

    std::string PubKey::to_string() const { return oxenc::to_base32z(begin(), end()); }

    PubKey& PubKey::operator=(const uint8_t* ptr)
    {
        std::copy(ptr, ptr + SIZE, begin());
        return *this;
    }

    PubKey& PubKey::operator=(const PubKey& other)
    {
        std::memcpy(begin(), other.begin(), PUBKEYSIZE);
        return *this;
    }

    bool PubKey::operator<(const PubKey& other) const { return as_array() < other.as_array(); }

    bool PubKey::operator==(const PubKey& other) const { return as_array() == other.as_array(); }

    bool PubKey::operator!=(const PubKey& other) const { return !(*this == other); }
}  // namespace llarp
