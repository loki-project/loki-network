#include <llarp/path/path.hpp>

#include <common.hpp>

namespace llarp
{
    namespace path
    {
        void PathHopConfig_Init(py::module& mod)
        {
            auto str_func = [](PathHopConfig* hop) {
                std::string s = "Hop: [";
                s += RouterID(hop->rc.pubkey).ShortString();
                s += "] -> [";
                s += hop->upstream.ShortString();
                s += "]";
                return s;
            };
            py::class_<PathHopConfig>(mod, "PathHopConfig")
                .def_readonly("rc", &PathHopConfig::rc)
                .def_readonly("upstreamRouter", &PathHopConfig::upstream)
                .def_readonly("txid", &PathHopConfig::txID)
                .def_readonly("rxid", &PathHopConfig::rxID)
                .def("ToString", str_func)
                .def("__str__", str_func)
                .def("__repr__", str_func);
        }
    }  // namespace path
}  // namespace llarp
