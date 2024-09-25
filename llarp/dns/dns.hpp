#pragma once

#include <llarp/util/logging.hpp>

#include <cstdint>

namespace llarp::dns
{
    constexpr uint16_t qTypeSRV = 33;
    constexpr uint16_t qTypeAAAA = 28;
    constexpr uint16_t qTypeTXT = 16;
    constexpr uint16_t qTypeMX = 15;
    constexpr uint16_t qTypePTR = 12;
    constexpr uint16_t qTypeCNAME = 5;
    constexpr uint16_t qTypeNS = 2;
    constexpr uint16_t qTypeA = 1;

    constexpr uint16_t qClassIN = 1;

    constexpr uint16_t flags_QR = (1 << 15);
    constexpr uint16_t flags_AA = (1 << 10);
    constexpr uint16_t flags_TC = (1 << 9);
    constexpr uint16_t flags_RD = (1 << 8);
    constexpr uint16_t flags_RA = (1 << 7);
    constexpr uint16_t flags_RCODENameError = (3);
    constexpr uint16_t flags_RCODEServFail = (2);
    constexpr uint16_t flags_RCODENoError = (0);

}  // namespace llarp::dns
