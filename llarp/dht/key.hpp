#pragma once

#include <llarp/router_id.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/formattable.hpp>

#include <array>

namespace llarp::dht
{
    struct Key_t : public AlignedBuffer<32>
    {
        explicit Key_t(const uint8_t* buf) : AlignedBuffer<SIZE>(buf)
        {}

        explicit Key_t(const std::array<uint8_t, SIZE>& data) : AlignedBuffer<SIZE>(data)
        {}

        explicit Key_t(const AlignedBuffer<SIZE>& data) : AlignedBuffer<SIZE>(data)
        {}

        Key_t() : AlignedBuffer<SIZE>()
        {}

        /// get snode address string
        std::string SNode() const
        {
            const RouterID rid{as_array()};
            return rid.to_string();
        }

        StatusObject ExtractStatus() const;

        std::string to_string() const
        {
            return SNode();
        }

        Key_t operator^(const Key_t& other) const
        {
            Key_t dist;
            std::transform(begin(), end(), other.begin(), dist.begin(), std::bit_xor<uint8_t>());
            return dist;
        }

        bool operator==(const Key_t& other) const
        {
            return as_array() == other.as_array();
        }

        bool operator!=(const Key_t& other) const
        {
            return as_array() != other.as_array();
        }

        bool operator<(const Key_t& other) const
        {
            return as_array() < other.as_array();
        }

        bool operator>(const Key_t& other) const
        {
            return as_array() > other.as_array();
        }
    };
}  // namespace llarp::dht
