#include "key_manager.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/util/logging.hpp>

#include <system_error>

namespace llarp
{
    static auto logcat = log::Cat("keymanager");

    KeyManager::KeyManager() : is_initialized(false), backup_keys(false) {}

    static void enckeygen_hook(llarp::SecretKey& key)
    {
        return crypto::encryption_keygen(key);
    }

    static void transkeygen_hook(llarp::SecretKey& key)
    {
        key.zero();
        return crypto::encryption_keygen(key);
    }

    static void idkeygen_hook(llarp::SecretKey& key)
    {
        return crypto::identity_keygen(key);
    }

    bool KeyManager::initialize(const llarp::Config& config, bool gen_if_absent, bool is_snode)
    {
        logcat->set_level(log::Level::trace);  // TESTNET:
        if (is_initialized)
            return false;

        if (not is_snode)
        {
            log::debug(logcat, "Client generating keys...");
            crypto::identity_keygen(identity_key);
            crypto::encryption_keygen(encryption_key);
            crypto::encryption_keygen(transport_key);
            return true;
        }

        const fs::path root = config.router.data_dir;

        // utility function to assign a path, using the specified config parameter if present and
        // falling back to root / defaultName if not
        auto deriveFile = [&](const std::string& defaultName, const std::string& option) {
            if (option.empty())
                return root / defaultName;

            fs::path file(option);

            if (not file.is_absolute())
                file = root / file;

            return file;
        };

        rc_path = deriveFile(our_rc_filename, config.router.rc_file);
        log::trace(logcat, "Derived rc path: {}", rc_path.string());
        idkey_path = deriveFile(our_identity_filename, config.router.idkey_file);
        log::trace(logcat, "Derived id key path: {}", idkey_path.string());
        enckey_path = deriveFile(our_enc_key_filename, config.router.enckey_file);
        log::trace(logcat, "Derived enc key path: {}", enckey_path.string());
        transkey_path = deriveFile(our_transport_key_filename, config.router.transkey_file);
        log::trace(logcat, "Derived transport key path: {}", transkey_path.string());

        RemoteRC rc;

        if (auto exists = rc.read(rc_path); not exists)
        {
            log::trace(logcat, "Failed to read RC at path: {}", rc_path.string());
            if (not gen_if_absent)
            {
                log::error(logcat, "Could not read RC at path {}", rc_path);
                return false;
            }
        }
        else
        {
            log::trace(logcat, "Successfully read RC at path: {}", rc_path.string());
            if (backup_keys = (is_snode and not rc.verify()); backup_keys)
            {
                auto err = "RC (path:{}) is invalid or out of date"_format(rc_path);

                if (not gen_if_absent)
                {
                    log::error(logcat, "{}", err);
                    return false;
                }

                log::warning(logcat, "{}; backing up and regenerating private keys...", err);

                if (not copy_backup_keyfiles())
                {
                    log::error(logcat, "Failed to copy-backup key files");
                    return false;
                }
            }
        }

        if (not keygen(enckey_path, encryption_key, enckeygen_hook))
        {
            log::critical(logcat, "KeyManager::keygen failed to generate encryption key line:{}", __LINE__);
            return false;
        }

        if (not keygen(transkey_path, transport_key, transkeygen_hook))
        {
            log::critical(logcat, "KeyManager::keygen failed to generate transport key line:{}", __LINE__);
            return false;
        }

        if (not config.router.is_relay)
        {
            if (not keygen(idkey_path, identity_key, idkeygen_hook))
            {
                log::critical(logcat, "KeyManager::keygen failed to generate identity key line:{}", __LINE__);
                return false;
            }
        }

        is_initialized = true;
        return true;
    }

    bool KeyManager::copy_backup_keyfile(const fs::path& filepath)
    {
        auto findFreeBackupFilename = [](const fs::path& filepath) {
            for (int i = 0; i < 9; i++)
            {
                auto ext = ".{}.bak"_format(i);
                fs::path newPath = filepath;
                newPath += ext;

                if (not fs::exists(newPath))
                    return newPath;
            }
            return fs::path();
        };

        std::error_code ec;
        bool exists = fs::exists(filepath, ec);

        if (ec)
        {
            log::error(logcat, "Could not determine status of file (path:{}): {}", filepath, ec.message());
            return false;
        }

        if (not exists)
        {
            log::info(logcat, "File (path:{}) does not exist; no backup needed", filepath);
            return true;
        }

        fs::path newFilepath = findFreeBackupFilename(filepath);
        if (newFilepath.empty())
        {
            log::warning(logcat, "Could not find an appropriate backup filename for file (path:{})", filepath);
            return false;
        }

        log::info(logcat, "Backing up (moving) key file at {} to {}...", filepath, newFilepath);

        fs::rename(filepath, newFilepath, ec);
        if (ec)
        {
            log::error(logcat, "Failed to move key file {}", ec.message());
            return false;
        }

        return true;
    }

    bool KeyManager::copy_backup_keyfiles() const
    {
        std::vector<fs::path> files = {rc_path, idkey_path, enckey_path, transkey_path};

        for (auto& filepath : files)
        {
            if (not copy_backup_keyfile(filepath))
                return false;
        }

        return true;
    }

    bool KeyManager::keygen(fs::path path, llarp::SecretKey& key, std::function<void(llarp::SecretKey& key)> keygen)
    {
        if (not fs::exists(path))
        {
            log::debug(logcat, "Generating new key (path:{})", path);
            keygen(key);

            if (!key.write_to_file(path))
            {
                log::error(logcat, "Failed to save new key!");
                return false;
            }
        }

        log::debug(logcat, "Loading key from file (path:{})", path);
        return key.load_from_file(path);
    }

}  // namespace llarp
