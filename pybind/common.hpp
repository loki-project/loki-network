#pragma once
#include <llarp/util/fs.hpp>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <unordered_map>

namespace py = pybind11;

namespace llarp
{
    void Logger_Init(py::module& mod);

    void Context_Init(py::module& mod);

    void CryptoTypes_Init(py::module& mod);

    void Router_Init(py::module& mod);

    void RouterID_Init(py::module& mod);

    void RouterContact_Init(py::module& mod);

    void Config_Init(py::module& mod);

    void PathTypes_Init(py::module& mod);

    void PeerDb_Init(py::module& mod);

    void PeerStats_Init(py::module& mod);

    namespace dht
    {
        void DHTTypes_Init(py::module& mod);
    }

    namespace path
    {
        void PathHopConfig_Init(py::module& mod);
    }

    namespace handlers
    {
        void PyHandler_Init(py::module& mod);
    }

    namespace service
    {
        void Address_Init(py::module& mod);
    }

}  // namespace llarp

namespace tooling
{
    void RouterHive_Init(py::module& mod);

    void RouterEvent_Init(py::module& mod);

    void HiveContext_Init(py::module& mod);

    void HiveRouter_Init(py::module& mod);
}  // namespace tooling
