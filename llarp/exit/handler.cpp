#include "handler.hpp"

#include <llarp/router/router.hpp>

#include <memory>
#include <stdexcept>

namespace llarp::exit
{
    Handler::Handler(std::string name, Router& r) : handlers::RemoteHandler{std::move(name), r}
    {}
}  // namespace llarp::exit
