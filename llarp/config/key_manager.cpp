#include "key_manager.hpp"

#include <llarp/crypto/crypto.hpp>
#include <llarp/crypto/types.hpp>
#include <llarp/util/logging.hpp>

#include <system_error>

namespace llarp
{
    KeyManager::KeyManager() : is_initialized(false), backup_keys(false)
    {}

    bool KeyManager::initialize(const llarp::Config& config, bool gen_if_absent, bool is_snode)
    {
        if (is_initialized)
            return false;

        if (not is_snode)
        {
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
        idkey_path = deriveFile(our_identity_filename, config.router.idkey_file);
        enckey_path = deriveFile(our_enc_key_filename, config.router.enckey_file);
        transkey_path = deriveFile(our_transport_key_filename, config.router.transkey_file);

        RemoteRC rc;

        if (auto exists = rc.read(rc_path); not exists)
        {
            if (not gen_if_absent)
            {
                log::error(logcat, "Could not read RC at path {}", rc_path);
                return false;
            }
        }
        else
        {
            if (backup_keys = (is_snode and not rc.verify()); backup_keys)
            {
                auto err = "RC (path:{}) is invalid or out of date"_format(rc_path);

                if (not gen_if_absent)
                {
                    log::error(logcat, err);
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

        // load encryption key
        auto enckey_gen = [](llarp::SecretKey& key) { llarp::crypto::encryption_keygen(key); };
        if (not keygen(enckey_path, encryption_key, enckey_gen))
        {
            log::critical(logcat, "KeyManager::keygen failed to generate encryption key line:{}", __LINE__);
            return false;
        }

        // TODO: transport key (currently done in LinkLayer)
        auto transkey_gen = [](llarp::SecretKey& key) {
            key.zero();
            crypto::encryption_keygen(key);
        };

        if (not keygen(transkey_path, transport_key, transkey_gen))
        {
            log::critical(logcat, "KeyManager::keygen failed to generate transport key line:{}", __LINE__);
            return false;
        }

        if (not config.router.is_relay)
        {
            // load identity key or create if needed
            auto idkey_gen = [](llarp::SecretKey& key) {
                // TODO: handle generating from service node seed
                llarp::crypto::identity_keygen(key);
            };

            if (not keygen(idkey_path, identity_key, idkey_gen))
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
                std::string ext("." + std::to_string(i) + ".bak");
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
            LogError("Could not determine status of file ", filepath, ": ", ec.message());
            return false;
        }

        if (not exists)
        {
            LogInfo("File ", filepath, " doesn't exist; no backup needed");
            return true;
        }

        fs::path newFilepath = findFreeBackupFilename(filepath);
        if (newFilepath.empty())
        {
            LogWarn("Could not find an appropriate backup filename for", filepath);
            return false;
        }

        LogInfo("Backing up (moving) key file ", filepath, " to ", newFilepath, "...");

        fs::rename(filepath, newFilepath, ec);
        if (ec)
        {
            LogError("Failed to move key file ", ec.message());
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
            LogInfo("Generating new key", path);
            keygen(key);

            if (!key.write_to_file(path))
            {
                LogError("Failed to save new key");
                return false;
            }
        }
        LogDebug("Loading key from file ", path);
        return key.load_from_file(path);
    }

}  // namespace llarp
