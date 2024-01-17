#include "auth.hpp"

#include <llarp/router/router.hpp>
#include <llarp/service/protocol.hpp>
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

    void FileAuthPolicy::authenticate_async(
        std::shared_ptr<service::ProtocolMessage> msg, std::function<void(std::string, bool)> hook)
    {
        auto reply = router().loop()->make_caller([tag = msg->tag, hook, self = shared_from_this()](AuthResult result) {
            {
                util::Lock _lock{self->_m};
                self->_pending.erase(tag);
            }
            hook(result.reason, result.code == AuthCode::ACCEPTED);
        });
        {
            util::Lock _lock{_m};
            _pending.emplace(msg->tag);
        }
        if (msg->proto == service::ProtocolType::Auth)
        {
            router().queue_disk_io(
                [self = shared_from_this(),
                 auth = AuthInfo{std::string{reinterpret_cast<const char*>(msg->payload.data()), msg->payload.size()}},
                 reply]() {
                    try
                    {
                        reply(self->check_files(auth));
                    }
                    catch (std::exception& ex)
                    {
                        reply(AuthResult{AuthCode::FAILED, ex.what()});
                    }
                });
        }
        else
            reply(AuthResult{AuthCode::REJECTED, "protocol error"});
    }

    bool FileAuthPolicy::auth_async_pending(service::SessionTag tag) const
    {
        util::Lock _lock{_m};
        return _pending.count(tag);
    }
}  // namespace llarp::auth
