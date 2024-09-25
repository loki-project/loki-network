#include <llarp/dht/key.hpp>

#include <common.hpp>
#include <pybind11/operators.h>

namespace llarp
{
    namespace dht
    {
        void DHTTypes_Init(py::module& mod)
        {
            py::class_<Key_t>(mod, "DHTKey")
                .def(py::self == py::self)
                .def(py::self < py::self)
                .def(py::self ^ py::self)
                .def("distance", [](const Key_t* const lhs, const Key_t* const rhs) { return *lhs ^ *rhs; })
                .def("ShortString", [](const Key_t* const key) {
                    return llarp::RouterID(key->as_array()).ShortString();
                });
        }

    }  // namespace dht
}  // namespace llarp
