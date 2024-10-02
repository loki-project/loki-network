#pragma once

#include "key.hpp"

#include <llarp/contact/router_contact.hpp>
#include <llarp/service/intro_set.hpp>

#include <utility>

namespace llarp::dht
{
    struct RCNode
    {
        RouterContact rc;
        Key_t ID;

        RCNode() { ID.zero(); }

        RCNode(const RouterContact& other) : rc(other), ID(other.router_id()) {}

        nlohmann::json ExtractStatus() const { return rc.extract_status(); }

        bool operator<(const RCNode& other) const { return rc.timestamp() < other.rc.timestamp(); }
    };

    struct ISNode
    {
        service::EncryptedIntroSet introset;

        Key_t ID;

        ISNode() { ID.zero(); }

        ISNode(service::EncryptedIntroSet other) : introset(std::move(other))
        {
            ID = Key_t(introset.derived_signing_key.as_array());
        }

        nlohmann::json ExtractStatus() const { return introset.ExtractStatus(); }

        bool operator<(const ISNode& other) const { return introset.signed_at < other.introset.signed_at; }
    };
}  // namespace llarp::dht
