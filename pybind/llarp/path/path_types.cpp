#include <llarp/path/path.hpp>

#include <common.hpp>
#include <pybind11/operators.h>

namespace llarp
{
    void PathTypes_Init(py::module& mod)
    {
        py::class_<PathID_t>(mod, "PathID")
            .def(py::self == py::self)
            .def("ShortHex", &PathID_t::ShortHex)
            .def("__str__", &PathID_t::ShortHex)
            .def("__repr__", &PathID_t::ShortHex);
    }

}  // namespace llarp
