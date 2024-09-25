#include <llarp/config/config.hpp>
#include <llarp/peerstats/peer_db.hpp>
#include <llarp/peerstats/types.hpp>

#include <common.hpp>
#include <netinet/in.h>

namespace llarp
{
    void PeerDb_Init(py::module& mod)
    {
        using PeerDb_ptr = std::shared_ptr<PeerDb>;
        py::class_<PeerDb, PeerDb_ptr>(mod, "PeerDb").def("getCurrentPeerStats", &PeerDb::getCurrentPeerStats);
    }

    void PeerStats_Init(py::module& mod)
    {
        py::class_<PeerStats>(mod, "PeerStats")
            .def_readwrite("routerId", &PeerStats::routerId)
            .def_readwrite("numConnectionAttempts", &PeerStats::numConnectionAttempts)
            .def_readwrite("numConnectionSuccesses", &PeerStats::numConnectionSuccesses)
            .def_readwrite("numConnectionRejections", &PeerStats::numConnectionRejections)
            .def_readwrite("numConnectionTimeouts", &PeerStats::numConnectionTimeouts)
            .def_readwrite("numPathBuilds", &PeerStats::numPathBuilds)
            .def_readwrite("numPacketsAttempted", &PeerStats::numPacketsAttempted)
            .def_readwrite("numPacketsSent", &PeerStats::numPacketsSent)
            .def_readwrite("numPacketsDropped", &PeerStats::numPacketsDropped)
            .def_readwrite("numPacketsResent", &PeerStats::numPacketsResent)
            .def_readwrite("numDistinctRCsReceived", &PeerStats::numDistinctRCsReceived)
            .def_readwrite("numLateRCs", &PeerStats::numLateRCs)
            .def_readwrite("peakBandwidthBytesPerSec", &PeerStats::peakBandwidthBytesPerSec)
            .def_readwrite("longestRCReceiveInterval", &PeerStats::longestRCReceiveInterval)
            .def_readwrite("leastRCRemainingLifetime", &PeerStats::leastRCRemainingLifetime)
            .def_readwrite("lastRCUpdated", &PeerStats::lastRCUpdated)
            .def_readwrite("stale", &PeerStats::stale);
    }
}  // namespace llarp
