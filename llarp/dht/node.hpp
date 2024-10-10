#pragma once

#include "key.hpp"

#include <llarp/contact/client_contact.hpp>
#include <llarp/contact/relay_contact.hpp>
#include <llarp/service/intro_set.hpp>

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
        EncryptedClientContact client_contact;
        Key_t ID;

        CCNode() { ID.zero(); }

        CCNode(EncryptedClientContact other) : client_contact{std::move(other)}, ID{client_contact.blinded_pubkey} {}

        bool operator<(const CCNode& other) const { return client_contact.signed_at < other.client_contact.signed_at; }
    };

    struct ISNode
    {
        service::EncryptedIntroSet introset;
        Key_t ID;

        ISNode() { ID.zero(); }

        ISNode(service::EncryptedIntroSet other) : introset(std::move(other)), ID{introset.derived_signing_key} {}

        nlohmann::json ExtractStatus() const { return introset.ExtractStatus(); }

        bool operator<(const ISNode& other) const { return introset.signed_at < other.introset.signed_at; }
    };
}  // namespace llarp::dht
