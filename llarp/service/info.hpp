#pragma once

#include "address.hpp"
#include "vanity.hpp"

#include <llarp/crypto/types.hpp>
#include <llarp/util/bencode.hpp>

#include <oxenc/bt.h>

#include <optional>

namespace
{
    static auto info_cat = llarp::log::Cat("lokinet.info");
}  // namespace

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

        void RandomizeVanity()
        {
            vanity.Randomize();
        }

        bool verify(uint8_t* buf, size_t size, const Signature& sig) const;

        const PubKey& EncryptionPublicKey() const
        {
            if (_cached_addr.IsZero())
            {
                CalculateAddress(_cached_addr.as_array());
            }
            return enckey;
        }

        bool Update(const byte_t* sign, const byte_t* enc, const std::optional<VanityNonce>& nonce = {});

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
            return Addr() < other.Addr();
        }

        std::string ToString() const;

        /// .loki address
        std::string Name() const;

        bool UpdateAddr();

        const Address& Addr() const
        {
            if (_cached_addr.IsZero())
            {
                CalculateAddress(_cached_addr.as_array());
            }
            return _cached_addr;
        }

        /// calculate our address
        bool CalculateAddress(std::array<byte_t, 32>& data) const;

        bool BDecode(llarp_buffer_t* buf)
        {
            if (not bencode_decode_dict(*this, buf))
                return false;
            return UpdateAddr();
        }

        void bt_decode(oxenc::bt_dict_consumer&);

        void bt_encode(oxenc::bt_dict_producer& btdp) const;

        bool decode_key(const llarp_buffer_t& key, llarp_buffer_t* buf);
    };
}  // namespace llarp::service

template <>
constexpr inline bool llarp::IsToStringFormattable<llarp::service::ServiceInfo> = true;
