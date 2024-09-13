#include "key_manager.hpp"

#include "crypto.hpp"

#include <llarp/config/config.hpp>
#include <llarp/util/logging.hpp>

#include <system_error>

namespace llarp
{
    static auto logcat = log::Cat("keymanager");

    std::shared_ptr<KeyManager> KeyManager::make(const Config& config, bool is_relay)
    {
        return std::shared_ptr<KeyManager>{new KeyManager{config, is_relay}};
    }

    KeyManager::KeyManager(const Config& config, bool is_relay) : is_initialized(false)
    {
        if (not _initialize(config, is_relay))
            throw std::runtime_error{"KeyManager failed to initialize"};
    }

    bool KeyManager::_initialize(const Config& config, bool is_relay)
    {
        logcat->set_level(log::Level::trace);  // TESTNET:
        if (is_initialized)
            return false;

        if (not is_relay)
        {
            if (config.network.keyfile.has_value() and identity_key.load_from_file(*config.network.keyfile))
            {
                log::info(logcat, "Successfully loaded persistent client key from config path");
            }
            else
            {
                log::debug(logcat, "Client generating identity key...");
                crypto::identity_keygen(identity_key);
            }

            public_key = seckey_to_pubkey(identity_key);
            log::info(logcat, "Client public key: {}", public_key);

            is_initialized = true;
        }
        else
        {
            const auto& root = config.router.data_dir;
            auto& conf_rc = config.router.rc_file;

            rc_path =
                conf_rc.has_value() ? conf_rc->is_absolute() ? *conf_rc : root / *conf_rc : root / our_rc_filename;

            log::trace(logcat, "Derived rc path: {}", rc_path.string());

            RemoteRC rc;

            if (rc.read(rc_path))
            {
                log::trace(logcat, "Successfully read RC at path: {}", rc_path.c_str());
                is_initialized = true;
            }
            else
                log::error(logcat, "Could not read RC at path {}", rc_path);
        }

        return is_initialized;
    }

    void KeyManager::update_idkey(SecretKey&& newkey)
    {
        identity_key = std::move(newkey);
        public_key = seckey_to_pubkey(identity_key);
        log::info(logcat, "Relay key manager updated secret key; new public key: {}", public_key);
    }
}  // namespace llarp
