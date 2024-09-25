#include "common.hpp"

#include <llarp/router/router.hpp>
#include <llarp/tooling/hive_router.hpp>

namespace llarp
{
    void Router_Init(py::module& mod)
    {
        py::class_<Router, std::shared_ptr<Router>>(mod, "Router")
            .def("rc", &Router::rc)
            .def("Stop", &Router::Stop)
            .def("peerDb", &Router::peerDb);
    }

}  // namespace llarp

namespace tooling
{
    void HiveRouter_Init(py::module& mod)
    {
        py::class_<HiveRouter, llarp::Router, std::shared_ptr<HiveRouter>>(mod, "HiveRouter")
            .def("disableGossiping", &HiveRouter::disableGossiping)
            .def("enableGossiping", &HiveRouter::enableGossiping);
    }
}  // namespace tooling
