#pragma once

#include <libntrup/ntru.h>

#include <cstdint>

static constexpr uint32_t PUBKEYSIZE = 32;
static constexpr uint32_t SECKEYSIZE = 64;
static constexpr uint32_t NONCESIZE = 24;
static constexpr uint32_t SHAREDKEYSIZE = 32;
static constexpr uint32_t HASHSIZE = 64;
static constexpr uint32_t SHORTHASHSIZE = 32;
static constexpr uint32_t HMACSECSIZE = 32;
static constexpr uint32_t SIGSIZE = 64;
static constexpr uint32_t TUNNONCESIZE = 32;
static constexpr uint32_t HMACSIZE = 32;
static constexpr uint32_t PATHIDSIZE = 16;

static constexpr uint32_t PQ_CIPHERTEXTSIZE = crypto_kem_CIPHERTEXTBYTES;
static constexpr uint32_t PQ_PUBKEYSIZE = crypto_kem_PUBLICKEYBYTES;
static constexpr uint32_t PQ_SECRETKEYSIZE = crypto_kem_SECRETKEYBYTES;
static constexpr uint32_t PQ_KEYPAIRSIZE = (PQ_SECRETKEYSIZE + PQ_PUBKEYSIZE);
