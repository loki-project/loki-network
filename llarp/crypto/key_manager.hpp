#pragma once

#include "types.hpp"

#include <llarp/contact/router_id.hpp>

#include <atomic>

namespace llarp
{
    struct Config;

    namespace handlers
    {
        class SessionEndpoint;
    }

    // KeyManager manages the cryptographic keys stored on disk for the local
    // node. This includes private keys as well as the self-signed router contact
    // file (e.g. "self.signed").
    //
    // Keys are either read from disk if they exist and are valid (see below) or
    // are generated and written to disk.
    struct KeyManager
    {
        friend struct Router;
        friend class handlers::SessionEndpoint;

      private:
        KeyManager(const Config& config, bool is_relay);

        std::atomic<bool> is_initialized{false};

        // Initializes keys using the provided config, loading from disk. Must be called
        // prior to obtaining any keys; blocks on I/O
        bool _initialize(const Config& config, bool is_relay);

      protected:
        static std::shared_ptr<KeyManager> make(const Config& config, bool is_relay);

        Ed25519SecretKey identity_key;
        Ed25519PrivateData identity_data;
        RouterID public_key;

        fs::path rc_path;

        void update_idkey(Ed25519SecretKey&& newkey);

        Ed25519PrivateData derive_subkey(uint64_t domain = 1) const;

      public:
        const RouterID& router_id() const { return public_key; }
    };

}  // namespace llarp
