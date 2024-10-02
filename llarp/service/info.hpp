#pragma once

#include <llarp/address/address.hpp>
#include <llarp/constants/proto.hpp>
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
        mutable NetworkAddress _cached_addr;

      public:
        uint64_t version = llarp::constants::proto_version;

        bool verify(uint8_t* buf, size_t size, const Signature& sig) const;

        const PubKey& encryption_pubkey() const
        {
            if (_cached_addr.is_empty())
                calculate_address(_cached_addr.pubkey());

            return enckey;
        }

        bool update(const uint8_t* sign, const uint8_t* enc);

        bool operator==(const ServiceInfo& other) const
        {
            return std::tie(enckey, version) == std::tie(other.enckey, other.version);
        }

        bool operator!=(const ServiceInfo& other) const { return !(*this == other); }

        bool operator<(const ServiceInfo& other) const { return address() < other.address(); }

        std::string to_string() const;

        /// .loki address
        std::string name() const;

        bool update_address();

        const NetworkAddress& address() const
        {
            if (_cached_addr.is_empty())
                calculate_address(_cached_addr.pubkey());

            return _cached_addr;
        }

        /// calculate our address
        bool calculate_address(PubKey& data) const;

        bool bt_decode(std::string_view buf);

        void bt_decode(oxenc::bt_dict_consumer& btdc);

        void bt_encode(oxenc::bt_dict_producer& btdp) const;
    };
}  // namespace llarp::service
