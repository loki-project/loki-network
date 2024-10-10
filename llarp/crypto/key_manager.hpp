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
    //
    // In addition, the KeyManager detects when the keys obsolete (e.g. as a
    // result of a software upgrade) and backs up existing keys before writing
    // out new ones.
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
        RouterID public_key;

        fs::path rc_path;

        void update_idkey(Ed25519SecretKey&& newkey);

        Ed25519Hash derive_subkey() const;

      public:
        //

        const RouterID& router_id() const { return public_key; }
    };

}  // namespace llarp
