#include "auth.hpp"

#include <llarp/router/router.hpp>
#include <llarp/util/str.hpp>

namespace llarp::auth
{
    AuthResult FileAuthPolicy::check_files(const AuthInfo& info) const
    {
        for (const auto& f : _files)
        {
            fs::ifstream i{f};
            std::string line{};
            while (std::getline(i, line))
            {
                // split off comments
                const auto parts = split_any(line, "#;", true);
                if (auto part = parts[0]; not parts.empty() and not parts[0].empty())
                {
                    // split off whitespaces and check password
                    if (check_passwd(std::string{TrimWhitespace(part)}, info.token))
                        return AuthResult{AuthCode::ACCEPTED, "accepted by whitelist"};
                }
            }
        }
        return AuthResult{AuthCode::REJECTED, "rejected by whitelist"};
    }

    bool FileAuthPolicy::check_passwd(std::string hash, std::string challenge) const
    {
        switch (_type)
        {
            case AuthFileType::PLAIN:
                return hash == challenge;
            case AuthFileType::HASHES:
#ifdef HAVE_CRYPT
                return crypto::check_passwd_hash(std::move(hash), std::move(challenge));
#endif
            default:
                return false;
        }
    }

}  // namespace llarp::auth
