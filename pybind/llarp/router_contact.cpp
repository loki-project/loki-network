#include "common.hpp"

#include <llarp/dht/key.hpp>
#include <llarp/relay_contact.hpp>
#include <llarp/util/time.hpp>

namespace llarp
{
    void RelayContact_Init(py::module& mod)
    {
        py::class_<RelayContact>(mod, "RelayContact")
            .def(py::init<>())
            .def_property_readonly(
                "routerID", [](const RelayContact* const rc) -> llarp::RouterID { return llarp::RouterID(rc->pubkey); })
            .def_property_readonly(
                "AsDHTKey",
                [](const RelayContact* const rc) -> llarp::dht::Key_t {
                    return llarp::dht::Key_t{rc->pubkey.as_array()};
                })
            .def("ReadFile", &RelayContact::Read)
            .def("WriteFile", &RelayContact::Write)
            .def("ToString", &RelayContact::ToString)
            .def("__str__", &RelayContact::ToString)
            .def("__repr__", &RelayContact::ToString)
            .def("Verify", [](const RelayContact* const rc) -> bool {
                const std::chrono::milliseconds now = llarp::time_now_ms();
                return rc->Verify(now);
            });
    }
}  // namespace llarp
