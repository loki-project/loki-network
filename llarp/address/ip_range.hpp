#pragma once

#include <llarp/util/formattable.hpp>

#include <oxen/quic.hpp>

namespace llarp
{
    struct IPRange
    {
       private:
        oxen::quic::Address addr;
        uint8_t mask;

        bool _is_ipv4;

       public:
        IPRange() = default;
        explicit IPRange(std::string a, uint8_t m) : addr{std::move(a), 0}, mask{m}, _is_ipv4{addr.is_ipv4()}
        {}
        explicit IPRange(oxen::quic::Address a, uint8_t m) : addr{a}, mask{m}, _is_ipv4{addr.is_ipv4()}
        {}

        std::string to_string() const
        {
            return addr.to_string() + "/" + std::to_string(mask);
        }

        bool from_string(std::string arg);

        bool is_ipv4() const
        {
            return _is_ipv4;
        }
    };

    template <>
    inline constexpr bool IsToStringFormattable<IPRange> = true;
}  //  namespace llarp
