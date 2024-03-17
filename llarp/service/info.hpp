#pragma once

#include "address.hpp"
#include "vanity.hpp"

#include <llarp/crypto/types.hpp>

#include <oxenc/bt.h>

#include <optional>

namespace llarp::service
{
    struct ServiceInfo
    {
      private:
        PubKey enckey;
        PubKey signkey;
        mutable Address _cached_addr;

      public:
        VanityNonce vanity;
        uint64_t version = llarp::constants::proto_version;

        void randomize_vanity()
        {
            vanity.Randomize();
        }

        bool verify(uint8_t* buf, size_t size, const Signature& sig) const;

        const PubKey& encryption_pubkey() const
        {
            if (_cached_addr.is_zero())
            {
                calculate_address(_cached_addr.as_array());
            }
            return enckey;
        }

        bool update(const uint8_t* sign, const uint8_t* enc, const std::optional<VanityNonce>& nonce = {});

        bool operator==(const ServiceInfo& other) const
        {
            return enckey == other.enckey && signkey == other.signkey && version == other.version
                && vanity == other.vanity;
        }

        bool operator!=(const ServiceInfo& other) const
        {
            return !(*this == other);
        }

        bool operator<(const ServiceInfo& other) const
        {
            return address() < other.address();
        }

        std::string to_string() const;

        /// .loki address
        std::string name() const;

        bool update_address();

        const Address& address() const
        {
            if (_cached_addr.is_zero())
            {
                calculate_address(_cached_addr.as_array());
            }
            return _cached_addr;
        }

        /// calculate our address
        bool calculate_address(std::array<uint8_t, 32>& data) const;

        bool bt_decode(std::string_view buf);

        void bt_decode(oxenc::bt_dict_consumer& btdc);

        void bt_encode(oxenc::bt_dict_producer& btdp) const;
    };
}  // namespace llarp::service

template <>
inline constexpr bool llarp::IsToStringFormattable<llarp::service::ServiceInfo> = true;
