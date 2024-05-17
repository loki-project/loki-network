#pragma once

#include "config.hpp"

// #include <llarp/crypto/types.hpp>
// #include <llarp/router_contact.hpp>

#include <atomic>

namespace llarp
{
    /// KeyManager manages the cryptographic keys stored on disk for the local
    /// node. This includes private keys as well as the self-signed router contact
    /// file (e.g. "self.signed").
    ///
    /// Keys are either read from disk if they exist and are valid (see below) or
    /// are generated and written to disk.
    ///
    /// In addition, the KeyManager detects when the keys obsolete (e.g. as a
    /// result of a software upgrade) and backs up existing keys before writing
    /// out new ones.
    struct KeyManager
    {
        /// Utility function to backup a file by moving it. Attempts to find a new
        /// filename based on the original that doesn't exist, then moves it. The
        /// pattern used is originalFile.N.bak where N is the lowest integer
        /// matching a filename that doesn't exist.
        ///
        /// @param filepath is the name of the original file to backup.
        /// @return true if the file could be moved or didn't exist, false otherwise
        static bool copy_backup_keyfile(const fs::path& filepath);

        /// Constructor
        KeyManager();

        /// Initializes keys using the provided config, loading from disk. Must be called
        /// prior to obtaining any keys and blocks on I/O
        ///
        /// @param config should be a prepared config object
        /// @param genIfAbsent determines whether or not we will create files if they
        ///        do not exist.
        /// @param isSNode
        /// @return true on success, false otherwise
        bool initialize(const Config& config, bool genIfAbsent, bool isSNode);

        /// Obtain the self-signed RouterContact
        ///
        /// @param rc (out) will be modified to contian the RouterContact
        /// @return true on success, false otherwise
        bool gen_rc(llarp::RouterContact& rc) const;

        /// Return whether or not we need to backup keys as we load them
        bool needs_backup() const { return backup_keys; }

        llarp::SecretKey identity_key;
        llarp::SecretKey encryption_key;
        llarp::SecretKey transport_key;

        fs::path rc_path;
        fs::path idkey_path;
        fs::path enckey_path;
        fs::path transkey_path;

      private:
        std::atomic_bool is_initialized;
        std::atomic_bool backup_keys;

        /// Backup each key file (by copying, e.g. foo -> foo.bak)
        bool copy_backup_keyfiles() const;

        /// Load the key at a given filepath or create it
        ///
        /// @param keygen is a function that will generate the key if needed
        static bool keygen(fs::path filepath, llarp::SecretKey& key, std::function<void(llarp::SecretKey& key)> keygen);
    };

}  // namespace llarp
