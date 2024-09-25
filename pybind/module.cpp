#include "common.hpp"

#include <llarp/util/logging.hpp>

PYBIND11_MODULE(pyllarp, m)
{
    tooling::RouterHive_Init(m);
    tooling::RouterEvent_Init(m);
    llarp::Router_Init(m);
    tooling::HiveRouter_Init(m);
    llarp::PeerDb_Init(m);
    llarp::PeerStats_Init(m);
    llarp::RouterID_Init(m);
    llarp::RouterContact_Init(m);
    llarp::CryptoTypes_Init(m);
    llarp::Context_Init(m);
    tooling::HiveContext_Init(m);
    llarp::Config_Init(m);
    llarp::dht::DHTTypes_Init(m);
    llarp::PathTypes_Init(m);
    llarp::path::PathHopConfig_Init(m);
    llarp::handlers::PyHandler_Init(m);
    llarp::service::Address_Init(m);
    m.def("EnableDebug", []() { llarp::log::reset_level(llarp::log::Level::debug); });
    llarp::Logger_Init(m);
}
