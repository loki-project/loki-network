#include <llarp/handlers/pyhandler.hpp>
namespace llarp
{
    namespace handlers
    {
        void PyHandler_Init(py::module& mod)
        {
            py::class_<PythonEndpoint, PythonEndpoint_ptr>(mod, "Endpoint")
                .def(py::init<std::string, Context_ptr>())
                .def("SendTo", &PythonEndpoint::SendPacket)
                .def("OurAddress", &PythonEndpoint::GetOurAddress)
                .def_readwrite("GotPacket", &PythonEndpoint::handlePacket);
        }

    }  // namespace handlers

}  // namespace llarp
