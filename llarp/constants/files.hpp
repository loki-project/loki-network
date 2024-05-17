#pragma once
#include "platform.hpp"

#include <filesystem>

#ifndef _WIN32
#include <pwd.h>
#include <unistd.h>
#endif

// namespace fs
// {
//     using namespace std::filesystem;
// }

namespace fs = std::filesystem;

namespace llarp
{
    constexpr auto our_rc_filename = "self.signed";
    constexpr auto our_identity_filename = "identity.key";
    constexpr auto our_enc_key_filename = "encryption.key";
    constexpr auto our_transport_key_filename = "transport.key";

    constexpr auto nodedb_dirname = "nodedb";

    inline fs::path GetDefaultDataDir()
    {
        if constexpr (not platform::is_windows)
        {
            fs::path datadir{"/var/lib/lokinet"};
#ifndef _WIN32
            if (auto uid = geteuid())
            {
                if (auto* pw = getpwuid(uid))
                {
                    datadir = fs::path{pw->pw_dir} / ".lokinet";
                }
            }
#endif
            return datadir;
        }
        else
            return "C:\\ProgramData\\Lokinet";
    }

    inline fs::path GetDefaultConfigFilename()
    {
        return "lokinet.ini";
    }

    inline fs::path GetDefaultConfigPath()
    {
        return GetDefaultDataDir() / GetDefaultConfigFilename();
    }

    inline fs::path GetDefaultBootstrap()
    {
        return GetDefaultDataDir() / "bootstrap.signed";
    }

}  // namespace llarp
