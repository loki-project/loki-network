#pragma once

#include "key.hpp"

#include <llarp/contact/relay_contact.hpp>

namespace llarp::dht
{
    struct XorMetric
    {
        const Key_t us;

        XorMetric(const Key_t& ourKey) : us(ourKey) {}

        bool operator()(const Key_t& left, const Key_t& right) const { return (us ^ left) < (us ^ right); }

        bool operator()(const RelayContact& left, const RelayContact& right) const
        {
            return (left.router_id() ^ us) < (right.router_id() ^ us);
        }
    };
}  // namespace llarp::dht
