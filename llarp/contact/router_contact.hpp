#pragma once

#include "router_id.hpp"

#include <llarp/constants/version.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/dns/srv_data.hpp>
#include <llarp/net/net.hpp>
#include <llarp/router_version.hpp>
#include <llarp/util/aligned.hpp>
#include <llarp/util/buffer.hpp>
#include <llarp/util/file.hpp>
#include <llarp/util/time.hpp>

#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>
#include <oxenc/bt_producer.h>

#include <functional>
#include <vector>

namespace llarp
{
    inline static constexpr size_t NETID_SIZE{8};

    /// On the wire we encode the data as a dict containing:
    /// ""  -- the RC format version, which must be == RouterContact::Version for us to attempt to
    ///        parse the reset of the fields.  (Future versions might have backwards-compat support
    ///        for lower versions).
    /// "4" -- 6 byte packed IPv4 address & port: 4 bytes of IPv4 address followed by 2 bytes of
    ///        port, both encoded in network (i.e. big-endian) order.
    /// "6" -- optional 18 byte IPv6 address & port: 16 byte raw IPv6 address followed by 2 bytes
    ///        of port in network order.
    /// "i" -- optional network ID string of up to 8 bytes; this is omitted for the default network
    ///        ID ("lokinet") but included for others (such as "testnet" for testnet).
    /// "p" -- 32-byte router pubkey
    /// "t" -- timestamp when this RC record was created (which also implicitly determines when it
    ///        goes stale and when it expires).
    /// "v" -- lokinet version of the router; this is a three-byte packed value of
    ///        MAJOR, MINOR, PATCH, e.g. \x00\x0a\x03 for 0.10.3.
    /// "~" -- signature of all of the previous serialized data, signed by "p"

    /// RouterContact
    struct RouterContact
    {
        static constexpr uint8_t RC_VERSION = 0;

        /// Unit tests disable this to allow private IP ranges in RCs, which normally get rejected.
        inline static bool BLOCK_BOGONS = true;

        inline static std::string ACTIVE_NETID{LOKINET_DEFAULT_NETID};

        inline static constexpr size_t MAX_RC_SIZE = 1024;

        /// How long (from its signing time) before an RC is considered "stale".  Relays republish
        /// their RCs slightly more frequently than this so that ideally this won't happen.
        static constexpr auto STALE_AGE = 6h;

        /// How long (from its signing time) before an RC becomes "outdated".  Outdated records are
        /// used (e.g. for path building) only if there are no newer records available, such as
        /// might be the case when a client has been turned off for a while.
        static constexpr auto OUTDATED_AGE = 12h;

        /// How long before an RC becomes invalid (and thus deleted).
        static constexpr auto LIFETIME = 30 * 24h;

        ustring_view view() const { return _payload; }

        /// Getters for private attributes
        const oxen::quic::Address& addr() const { return _addr; }
        oxen::quic::Address addr() { return _addr; }

        const std::optional<oxen::quic::Address>& addr6() const { return _addr6; }

        const RouterID& router_id() const { return _router_id; }
        RouterID router_id() { return _router_id; }

        const rc_time& timestamp() const { return _timestamp; }
        rc_time timestamp() { return _timestamp; }

      protected:
        // advertised addresses
        oxen::quic::Address _addr;                  // refactor all 15 uses to use addr() method
        std::optional<oxen::quic::Address> _addr6;  // optional ipv6
        // public signing public key
        RouterID _router_id;

        rc_time _timestamp{};

        // Lokinet version at the time the RC was produced
        std::array<uint8_t, 3> _router_version;

        // In both Remote and Local RC's, the entire bt-encoded payload given at construction is
        // emplaced here.
        //
        //   In a RemoteRC, this value will be held for the lifetime of the object
        // s.t. it can be returned upon calls to ::bt_encode.
        //   In a LocalRC, this value will be supplanted any time a mutator is invoked, requiring
        // the re-signing of the payload.
        ustring _payload;

      public:
        /// should we serialize the exit info?
        static const bool serializeExit = true;

        nlohmann::json extract_status() const;

        nlohmann::json to_json() const { return extract_status(); }

        virtual std::string to_string() const
        {
            return "RC:['4'={} | 'i'='{}' | 'p'={} | 't'={} | v={}]"_format(
                _addr.to_string(), ACTIVE_NETID, _router_id, _timestamp.time_since_epoch().count(), RC_VERSION);
        }

        bool write(const fs::path& fname) const;

        auto operator<=>(const RouterContact& other) const
        {
            return std::tie(_router_id, _addr, _addr6, _timestamp, _router_version)
                <=> std::tie(other._router_id, other._addr, other._addr6, other._timestamp, other._router_version);
        }

        bool operator==(const RouterContact& other) const { return (*this <=> other) == 0; }

        bool operator<(const RouterContact& other) const { return _router_id < other._router_id; }

        virtual void clear() {}

        bool is_public_addressable() const;

        /// does this RC expire soon? default delta is 1 minute
        bool expires_within_delta(std::chrono::milliseconds now, std::chrono::milliseconds dlt = 1min) const;

        /// returns true if this RC is expired and should be removed
        bool is_expired(std::chrono::milliseconds now) const;

        /// returns time in ms until we expire or 0 if we have expired
        std::chrono::milliseconds time_to_expiry(std::chrono::milliseconds now) const;

        /// get the age of this RC in ms
        std::chrono::milliseconds age(std::chrono::milliseconds now) const;

        bool other_is_newer(const RouterContact& other) const { return _timestamp < other._timestamp; }

        bool is_obsolete_bootstrap() const;

        static bool is_obsolete(const RouterContact& rc);

        void bt_verify(oxenc::bt_dict_consumer& data, bool reject_expired = false) const;

        void bt_load(oxenc::bt_dict_consumer& data);

        static constexpr bool to_string_formattable = true;
    };

    struct RemoteRC;

    /// Extension of RouterContact used to store a local "RC," and inserts a RouterContact by
    /// re-parsing and sending it out. This sub-class contains a pubkey and all the other attributes
    /// required for signing and serialization
    ///
    /// Note: this class may be entirely superfluous, so it is used here as a placeholder until its
    /// marginal utility is determined. It may end up as a free-floating method that reads in
    /// parameters and outputs a bt-serialized string
    struct LocalRC final : public RouterContact
    {
        static LocalRC make(Ed25519SecretKey secret, oxen::quic::Address local);

      private:
        ustring _signature;
        Ed25519SecretKey _secret_key;

        void bt_sign(oxenc::bt_dict_producer& btdp);

        void bt_encode(oxenc::bt_dict_producer& btdp);

        LocalRC(Ed25519SecretKey secret, oxen::quic::Address local);

      public:
        LocalRC() = default;
        ~LocalRC() = default;

        RemoteRC to_remote();

        void resign();

        void clear() override
        {
            _addr = oxen::quic::Address{};
            _addr6.reset();
            _router_id.zero();
            _timestamp = {};
            _router_version.fill(0);
            _signature.clear();
        }

        auto operator<=>(const LocalRC& other) const
        {
            return std::tie(_router_id, _addr, _addr6, _timestamp, _router_version, _signature) <=> std::tie(
                       other._router_id,
                       other._addr,
                       other._addr6,
                       other._timestamp,
                       other._router_version,
                       other._signature);
        }

        bool operator==(const LocalRC& other) const { return (*this <=> other) == 0; }

        bool operator<(const LocalRC& other) const { return _router_id < other._router_id; }

        /// Mutators for the private member attributes. Calling on the mutators
        /// will clear the current signature and re-sign the RC
        void set_addr(oxen::quic::Address new_addr)
        {
            _addr = std::move(new_addr);
            resign();
        }

        void set_addr6(oxen::quic::Address new_addr)
        {
            _addr6 = std::move(new_addr);
            resign();
        }

        void set_router_id(RouterID rid)
        {
            _router_id = std::move(rid);
            resign();
        }

        void set_timestamp(std::chrono::milliseconds ts)
        {
            set_timestamp(rc_time{std::chrono::duration_cast<std::chrono::seconds>(ts)});
        }

        void set_timestamp(rc_time ts) { _timestamp = ts; }

        /// Sets RC timestamp to current system clock time
        void set_systime_timestamp() { set_timestamp(time_point_now()); }
    };

    /// Extension of RouterContact used in a "read-only" fashion. Parses the incoming RC to query
    /// the data in the constructor, eliminating the need for a ::verify method/
    struct RemoteRC final : public RouterContact
    {
      private:
        // this ctor is private because it doesn't set ::_payload
        explicit RemoteRC(oxenc::bt_dict_consumer btdc);

      public:
        RemoteRC() = default;
        explicit RemoteRC(std::string_view data) : RemoteRC{oxenc::bt_dict_consumer{data}}
        {
            _payload = {reinterpret_cast<const unsigned char*>(data.data()), data.size()};
        }
        explicit RemoteRC(ustring_view data) : RemoteRC{oxenc::bt_dict_consumer{data}} { _payload = data; }
        ~RemoteRC() = default;

        std::string_view view() const { return {reinterpret_cast<const char*>(_payload.data()), _payload.size()}; }

        bool verify() const;

        bool read(const fs::path& fname);

        void clear() override
        {
            _addr = oxen::quic::Address{};
            _addr6.reset();
            _router_id.zero();
            _timestamp = {};
            _router_version.fill(0);
        }

        auto operator<=>(const RemoteRC& other) const
        {
            return std::tie(_router_id, _addr, _addr6, _timestamp, _router_version)
                <=> std::tie(other._router_id, other._addr, other._addr6, other._timestamp, other._router_version);
        }

        bool operator==(const RemoteRC& other) const { return (*this <=> other) == 0; }

        bool operator<(const RemoteRC& other) const { return _router_id < other._router_id; }
    };
}  // namespace llarp

namespace std
{
    template <>
    struct hash<llarp::RouterContact>
    {
        virtual size_t operator()(const llarp::RouterContact& r) const
        {
            return std::hash<llarp::PubKey>{}(r.router_id());
        }
    };

    template <>
    struct hash<llarp::RemoteRC> : public hash<llarp::RouterContact>
    {};

    template <>
    struct hash<llarp::LocalRC> final : public hash<llarp::RouterContact>
    {};
}  // namespace std
