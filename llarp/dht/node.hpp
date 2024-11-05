#pragma once

#include "key.hpp"

#include <llarp/contact/client_contact.hpp>
#include <llarp/contact/relay_contact.hpp>

#include <utility>

namespace llarp::dht
{
    struct RCNode
    {
        RelayContact rc;
        Key_t ID;

        RCNode() { ID.zero(); }

        RCNode(const RelayContact& other) : rc(other), ID(other.router_id()) {}

        nlohmann::json ExtractStatus() const { return rc.extract_status(); }

        bool operator<(const RCNode& other) const { return rc.timestamp() < other.rc.timestamp(); }
    };

    struct CCNode
    {
        EncryptedClientContact ecc;
        Key_t ID;

        CCNode() { ID.zero(); }

        CCNode(EncryptedClientContact other) : ecc{std::move(other)}, ID{ecc.blinded_pubkey} {}

        nlohmann::json ExtractStatus() const { return nlohmann::json{{"key", ecc.key().to_string()}}; }

        bool operator<(const CCNode& other) const { return ecc.signed_at < other.ecc.signed_at; }
    };
}  // namespace llarp::dht
