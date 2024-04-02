#include "auth.hpp"

#include <llarp/router/router.hpp>

namespace llarp::auth
{
    SessionAuthPolicy::SessionAuthPolicy(Router& r, bool _snode_service, bool is_exit)
        : AuthPolicy{r}, _is_snode_service{_snode_service}, _is_exit_service{is_exit}
    {
        // These can both be false but CANNOT both be true
        if (_is_exit_service & _is_snode_service)
            throw std::runtime_error{"Cannot create SessionAuthPolicy for a remote exit and remote service!"};

        if (_is_snode_service)
            _session_key = _router.identity();
        else
            crypto::identity_keygen(_session_key);
    }

    bool SessionAuthPolicy::load_identity_from_file(const char* fname)
    {
        return _session_key.load_from_file(fname);
    }

}  // namespace llarp::auth
