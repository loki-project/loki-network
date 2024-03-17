#include <lokinet/lokinet_misc.h>
#include <spdlog/details/null_mutex.h>
#include <spdlog/sinks/base_sink.h>

#include <mutex>

namespace llarp::logging
{
    // Logger that calls a C function with the formatted log message
    template <typename Mutex>
    class CallbackSink : public spdlog::sinks::base_sink<Mutex>
    {
      private:
        lokinet_logger_func log_;
        lokinet_logger_sync sync_;
        void* ctx_;

      public:
        explicit CallbackSink(lokinet_logger_func log, lokinet_logger_sync sync = nullptr, void* context = nullptr)
            : log_{log}, sync_{sync}, ctx_{context}
        {}

      protected:
        void sink_it_(const spdlog::details::log_msg& msg) override
        {
            if (!log_)
                return;
            spdlog::memory_buf_t formatted;
            spdlog::sinks::base_sink<Mutex>::formatter_->format(msg, formatted);
            log_(fmt::to_string(formatted).c_str(), ctx_);
        }

        void flush_() override
        {
            if (sync_)
                sync_(ctx_);
        }
    };

    // Convenience aliases with or without thread safety
    using CallbackSink_mt = CallbackSink<std::mutex>;
    using CallbackSink_st = CallbackSink<spdlog::details::null_mutex>;

}  // namespace llarp::logging
