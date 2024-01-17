#include "auth.hpp"

#include <llarp/router/router.hpp>

namespace llarp::auth
{
    SessionAuthPolicy::SessionAuthPolicy(Router& r, const SecretKey& sk, bool _snode_service)
        : AuthPolicy{r}, _session_key{sk}, _is_snode_service{_snode_service}
    {
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
