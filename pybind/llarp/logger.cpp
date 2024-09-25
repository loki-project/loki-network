#include <llarp/util/logging.hpp>

#include <common.hpp>

#include <memory>

namespace llarp
{
    struct PyLogger
    {
        std::optional<llarp::log::Level> silenced;
    };

    void Logger_Init(py::module& mod)
    {
        py::class_<PyLogger>(mod, "LogContext")
            .def(py::init<>())
            .def_property(
                "shutup",
                [](PyLogger& self) { return self.silenced.has_value(); },
                [](PyLogger& self, bool shutup) {
                    if (shutup and not self.silenced)
                        self.silenced = llarp::log::get_level_default();
                    else if (not shutup and self.silenced)
                    {
                        llarp::log::reset_level(*self.silenced);
                        self.silenced.reset();
                    }
                });
    }
}  // namespace llarp
