#include <llarp.hpp>
#include <llarp/router/router.hpp>
#include <llarp/tooling/router_hive.hpp>

#include <common.hpp>
#include <pybind11/iostream.h>
#include <pybind11/stl.h>

namespace tooling
{
    void RouterHive_Init(py::module& mod)
    {
        using RouterHive_ptr = std::shared_ptr<RouterHive>;
        using Context_ptr = RouterHive::Context_ptr;
        using ContextVisitor = std::function<void(Context_ptr)>;

        py::class_<RouterHive, RouterHive_ptr>(mod, "RouterHive")
            .def(py::init<>())
            .def("AddRelay", &RouterHive::AddRelay)
            .def("AddClient", &RouterHive::AddClient)
            .def("StartRelays", &RouterHive::StartRelays)
            .def("StartClients", &RouterHive::StartClients)
            .def("StopAll", &RouterHive::StopRouters)
            .def(
                "ForEachRelay",
                [](RouterHive& hive, ContextVisitor visit) {
                    hive.ForEachRelay([visit](Context_ptr ctx) {
                        py::gil_scoped_acquire acquire;
                        visit(std::move(ctx));
                    });
                })
            .def(
                "ForEachClient",
                [](RouterHive& hive, ContextVisitor visit) {
                    hive.ForEachClient([visit](Context_ptr ctx) {
                        py::gil_scoped_acquire acquire;
                        visit(std::move(ctx));
                    });
                })
            .def(
                "ForEachRouter",
                [](RouterHive& hive, ContextVisitor visit) {
                    hive.ForEachRouter([visit](Context_ptr ctx) {
                        py::gil_scoped_acquire acquire;
                        visit(std::move(ctx));
                    });
                })
            .def("GetNextEvent", &RouterHive::GetNextEvent)
            .def("GetAllEvents", &RouterHive::GetAllEvents)
            .def("RelayConnectedRelays", &RouterHive::RelayConnectedRelays)
            .def("GetRelayRCs", &RouterHive::GetRelayRCs)
            .def("GetRelay", &RouterHive::GetRelay);
    }
}  // namespace tooling
