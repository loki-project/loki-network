#include "auth.hpp"

#include <llarp/router/router.hpp>

namespace llarp::auth
{
    SessionAuthPolicy::SessionAuthPolicy(Router& r, RouterID& remote, bool is_snode, bool is_exit)
        : AuthPolicy{r},
          _is_snode_service{is_snode},
          _is_exit_service{is_exit},
          _remote{NetworkAddress::from_pubkey(remote, not _is_snode_service)}
    {
        // These can both be false but CANNOT both be true
        if (_is_exit_service & _is_snode_service)
            throw std::runtime_error{"Cannot create SessionAuthPolicy for a remote exit and remote service!"};

        if (_is_snode_service)
            _session_key = _router.identity();
        else
            crypto::identity_keygen(_session_key);
    }

    std::optional<std::string_view> SessionAuthPolicy::fetch_auth_token()
    {
        std::optional<std::string_view> ret = std::nullopt;
        auto& exit_auths = _router.config()->network.exit_auths;

        if (auto itr = exit_auths.find(_remote); itr != exit_auths.end())
            ret = itr->second;

        return ret;
    }

    bool SessionAuthPolicy::load_identity_from_file(const char* fname)
    {
        return _session_key.load_from_file(fname);
    }

}  // namespace llarp::auth
