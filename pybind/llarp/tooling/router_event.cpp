#include <llarp/messages/relay_status.hpp>
#include <llarp/path/path.hpp>
#include <llarp/tooling/dht_event.hpp>
#include <llarp/tooling/path_event.hpp>
#include <llarp/tooling/peer_stats_event.hpp>
#include <llarp/tooling/rc_event.hpp>
#include <llarp/tooling/router_event.hpp>

#include <common.hpp>
#include <pybind11/stl.h>

namespace tooling
{
    void RouterEvent_Init(py::module& mod)
    {
        py::class_<RouterEvent>(mod, "RouterEvent")
            .def("__repr__", &RouterEvent::ToString)
            .def("__str__", &RouterEvent::ToString)
            .def_readonly("routerID", &RouterEvent::routerID)
            .def_readonly("triggered", &RouterEvent::triggered);

        py::class_<PathAttemptEvent, RouterEvent>(mod, "PathAttemptEvent")
            .def_readonly("hops", &PathAttemptEvent::hops);

        py::class_<PathRequestReceivedEvent, RouterEvent>(mod, "PathRequestReceivedEvent")
            .def_readonly("prevHop", &PathRequestReceivedEvent::prevHop)
            .def_readonly("nextHop", &PathRequestReceivedEvent::nextHop)
            .def_readonly("txid", &PathRequestReceivedEvent::txid)
            .def_readonly("rxid", &PathRequestReceivedEvent::rxid)
            .def_readonly("isEndpoint", &PathRequestReceivedEvent::isEndpoint);

        py::class_<PathStatusReceivedEvent, RouterEvent>(mod, "PathStatusReceivedEvent")
            .def_readonly("rxid", &PathStatusReceivedEvent::rxid)
            .def_readonly("status", &PathStatusReceivedEvent::rxid)
            .def_property_readonly("Successful", [](const PathStatusReceivedEvent* const ev) {
                return ev->status == llarp::LR_StatusRecord::SUCCESS;
            });

        py::class_<PubIntroSentEvent, RouterEvent>(mod, "DhtPubIntroSentEvent")
            .def_readonly("introsetPubkey", &PubIntroSentEvent::introsetPubkey)
            .def_readonly("relay", &PubIntroSentEvent::relay)
            .def_readonly("relayIndex", &PubIntroSentEvent::relayIndex);

        py::class_<PubIntroReceivedEvent, RouterEvent>(mod, "DhtPubIntroReceivedEvent")
            .def_readonly("from", &PubIntroReceivedEvent::from)
            .def_readonly("location", &PubIntroReceivedEvent::location)
            .def_readonly("relayOrder", &PubIntroReceivedEvent::relayOrder)
            .def_readonly("txid", &PubIntroReceivedEvent::txid);

        py::class_<GotIntroReceivedEvent, RouterEvent>(mod, "DhtGotIntroReceivedEvent")
            .def_readonly("from", &GotIntroReceivedEvent::From)
            .def_readonly("location", &GotIntroReceivedEvent::Introset)
            .def_readonly("relayOrder", &GotIntroReceivedEvent::RelayOrder)
            .def_readonly("txid", &GotIntroReceivedEvent::TxID);

        py::class_<RCGossipReceivedEvent, RouterEvent>(mod, "RCGossipReceivedEvent")
            .def_readonly("rc", &RCGossipReceivedEvent::rc)
            .def("LongString", &RCGossipReceivedEvent::LongString);

        py::class_<RCGossipSentEvent, RouterEvent>(mod, "RCGossipSentEvent")
            .def_readonly("rc", &RCGossipSentEvent::rc)
            .def("LongString", &RCGossipSentEvent::LongString);

        py::class_<FindRouterEvent, RouterEvent>(mod, "FindRouterEvent")
            .def_readonly("from", &FindRouterEvent::from)
            .def_readonly("iterative", &FindRouterEvent::iterative)
            .def_readonly("exploritory", &FindRouterEvent::exploritory)
            .def_readonly("txid", &FindRouterEvent::txid)
            .def_readonly("version", &FindRouterEvent::version);

        py::class_<FindRouterReceivedEvent, FindRouterEvent, RouterEvent>(mod, "FindRouterReceivedEvent");

        py::class_<FindRouterSentEvent, FindRouterEvent, RouterEvent>(mod, "FindRouterSentEvent");

        py::class_<LinkSessionEstablishedEvent, RouterEvent>(mod, "LinkSessionEstablishedEvent")
            .def_readonly("remoteId", &LinkSessionEstablishedEvent::remoteId)
            .def_readonly("inbound", &LinkSessionEstablishedEvent::inbound);

        py::class_<ConnectionAttemptEvent, RouterEvent>(mod, "ConnectionAttemptEvent")
            .def_readonly("remoteId", &ConnectionAttemptEvent::remoteId);
    }

}  // namespace tooling
