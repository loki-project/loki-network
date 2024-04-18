#include "session.hpp"

#include <llarp/router/router.hpp>

namespace llarp::session
{
    InboundSession::InboundSession(
        std::shared_ptr<path::Path> _path, NetworkAddress _r, handlers::LocalEndpoint& p, service::SessionTag _t)
        : BaseSession{std::move(_path)},
          _parent{p},
          _tag{std::move(_t)},
          _remote{std::move(_r)},
          _is_exit_node{_parent.is_exit_node()}
    {}

    void InboundSession::set_new_path(const std::shared_ptr<path::Path>& _new_path)
    {
        _current_path.reset(_new_path.get());
    }

    void InboundSession::set_new_tag(const service::SessionTag& tag)
    {
        _tag = tag;
    }
}  //  namespace llarp::session
