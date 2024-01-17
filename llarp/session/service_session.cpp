#include "session.hpp"

#include <llarp/router/router.hpp>

namespace llarp::session
{
    ServiceSession::ServiceSession(
        const RouterID& _remote,
        Router& r,
        size_t hop_len,
        EndpointBase& parent,
        std::shared_ptr<auth::SessionAuthPolicy> a)
        : BaseSession{_remote, r, hop_len, parent, a}, _is_snode_service{a->is_snode_service()}
    {}

}  //  namespace llarp::session
