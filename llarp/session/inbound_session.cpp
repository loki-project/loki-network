#include "session.hpp"

#include <llarp/router/router.hpp>

namespace llarp::session
{
    InboundSession::InboundSession(Router& r, std::shared_ptr<path::Path> _path, RouterID _r, EndpointBase& p)
        : _router{r}, _parent{p}, _remote{std::move(_r)}, _current_path{std::move(_path)}
    {}

    void InboundSession::set_new_path(const std::shared_ptr<path::Path>& _new_path)
    {
        _current_path.reset(_new_path.get());
    }
}  //  namespace llarp::session
