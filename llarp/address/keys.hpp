#pragma once

#include <llarp/crypto/constants.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/concept.hpp>

/** TODO:
    - re-configure string_view and ustring_view methods after deprecating RouterID

*/

namespace llarp
{
    struct PubKey : public AlignedBuffer<PUBKEYSIZE>
    {
        PubKey() = default;

        bool from_hex(const std::string& str);

        std::string to_string() const;

        explicit PubKey(const uint8_t* data) : AlignedBuffer<PUBKEYSIZE>{data} {}
        explicit PubKey(const std::array<uint8_t, PUBKEYSIZE>& data) : AlignedBuffer<PUBKEYSIZE>{data} {}
        explicit PubKey(ustring_view data) : AlignedBuffer<PUBKEYSIZE>{data.data()} {}
        explicit PubKey(std::string_view data) : PubKey{to_usv(data)} {}
        PubKey(const PubKey& other) : PubKey{other.data()} {}
        PubKey(PubKey&& other) : PubKey{other.data()} {}

        PubKey& operator=(const PubKey& other);

        // revisit this
        PubKey& operator=(const uint8_t* ptr);

        bool operator<(const PubKey& other) const;
        bool operator==(const PubKey& other) const;
        bool operator!=(const PubKey& other) const;
    };
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::PubKey> : public hash<llarp::AlignedBuffer<PUBKEYSIZE>>
    {};
}  //  namespace std
