#pragma once

// Header for making actual log statements such as llarp::log::Info and so on work.

#include <string>
#include <string_view>
#include <array>

#include <oxen/log.hpp>
#include <oxen/log/ring_buffer_sink.hpp>
#include "oxen/log/internal.hpp"

namespace llarp
{
  namespace log = oxen::log;
}

// Not ready to pollute these deprecation warnings everywhere yet
#if 0
#define LOKINET_LOG_DEPRECATED(Meth) \
  [[deprecated("Use formatted log::" #Meth "(cat, fmt, args...) instead")]]
#else
#define LOKINET_LOG_DEPRECATED(Meth)
#endif

// Deprecated loggers (in the top-level llarp namespace):
namespace llarp
{
  inline std::shared_ptr<log::RingBufferSink> logRingBuffer = nullptr;

  namespace log_detail
  {
    inline log::CategoryLogger legacy_logger = log::Cat("");

    template <typename>
    struct concat_args_fmt_impl;
    template <size_t... I>
    struct concat_args_fmt_impl<std::integer_sequence<size_t, I...>>
    {
      constexpr static std::array<char, sizeof...(I)> format{(I % 2 == 0 ? '{' : '}')...};
    };
    template <size_t N>
    constexpr std::string_view
    concat_args_fmt()
    {
      return std::string_view{
          concat_args_fmt_impl<std::make_index_sequence<2 * N>>::format.data(), 2 * N};
    }
  }  // namespace log_detail

  template <typename... T>
  struct LOKINET_LOG_DEPRECATED(Trace) LogTrace : log::trace<T...>
  {
    LogTrace(
        T&&... args,
        const log::source_location& location = log::source_location::current())
        : log::trace<T...>::trace{
            log_detail::legacy_logger,
            log_detail::concat_args_fmt<sizeof...(T)>(),
            std::forward<T>(args)...,
            location}
    {}
  };
  template <typename... T>
  struct LOKINET_LOG_DEPRECATED(Debug) LogDebug : log::debug<T...>
  {
    LogDebug(
        T&&... args,
        const log::source_location& location = log::source_location::current())
        : log::debug<T...>::debug{
            log_detail::legacy_logger,
            log_detail::concat_args_fmt<sizeof...(T)>(),
            std::forward<T>(args)...,
            location}
    {}
  };
  template <typename... T>
  struct LOKINET_LOG_DEPRECATED(Info) LogInfo : log::info<T...>
  {
    LogInfo(
        T&&... args,
        const log::source_location& location = log::source_location::current())
        : log::info<T...>::info{
            log_detail::legacy_logger,
            log_detail::concat_args_fmt<sizeof...(T)>(),
            std::forward<T>(args)...,
            location}
    {}
  };
  template <typename... T>
  struct LOKINET_LOG_DEPRECATED(Warning) LogWarn : log::warning<T...>
  {
    LogWarn(
        T&&... args,
        const log::source_location& location = log::source_location::current())
        : log::warning<T...>::warning{
            log_detail::legacy_logger,
            log_detail::concat_args_fmt<sizeof...(T)>(),
            std::forward<T>(args)...,
            location}
    {}
  };
  template <typename... T>
  struct LOKINET_LOG_DEPRECATED(Error) LogError : log::error<T...>
  {
    LogError(
        T&&... args,
        const log::source_location& location = log::source_location::current())
        : log::error<T...>::error{
            log_detail::legacy_logger,
            log_detail::concat_args_fmt<sizeof...(T)>(),
            std::forward<T>(args)...,
            location}
    {}
  };

  template <typename... T>
  LogTrace(T&&...) -> LogTrace<T...>;

  template <typename... T>
  LogDebug(T&&...) -> LogDebug<T...>;

  template <typename... T>
  LogInfo(T&&...) -> LogInfo<T...>;

  template <typename... T>
  LogWarn(T&&...) -> LogWarn<T...>;

  template <typename... T>
  LogError(T&&...) -> LogError<T...>;

}  // namespace llarp
