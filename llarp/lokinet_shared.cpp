

#include "lokinet.h"
#include "llarp.hpp"
#include <llarp/config/config.hpp>
#include <llarp/crypto/crypto_libsodium.hpp>

#include <llarp/router/abstractrouter.hpp>
#include <llarp/service/context.hpp>
#include <llarp/quic/tunnel.hpp>
#include <llarp/nodedb.hpp>

#include <mutex>

namespace
{
  struct Context : public llarp::Context
  {
    using llarp::Context::Context;

    std::shared_ptr<llarp::NodeDB>
    makeNodeDB() override
    {
      return std::make_shared<llarp::NodeDB>();
    }
  };
}  // namespace

struct lokinet_context
{
  std::mutex m_access;

  std::shared_ptr<llarp::Context> impl;
  std::shared_ptr<llarp::Config> config;

  std::unique_ptr<std::thread> runner;

  lokinet_context() : impl{std::make_shared<Context>()}, config{llarp::Config::EmbeddedConfig()}
  {}

  ~lokinet_context()
  {
    if (runner)
      runner->join();
  }

  /// acquire mutex for accessing this context
  [[nodiscard]] auto
  acquire()
  {
    return std::unique_lock{m_access};
  }

  [[nodiscard]] auto
  endpoint(std::string name = "default") const
  {
    return impl->router->hiddenServiceContext().GetEndpointByName(name);
  }

  std::unordered_map<int, bool> streams;

  void
  inbound_stream(int id)
  {
    streams[id] = true;
  }

  void
  outbound_stream(int id)
  {
    streams[id] = false;
  }
};

namespace
{
  std::unique_ptr<lokinet_context> g_context;

  void
  stream_error(lokinet_stream_result* result, int err)
  {
    std::memset(result, 0, sizeof(lokinet_stream_result));
    result->error = err;
  }

  void
  stream_okay(lokinet_stream_result* result, std::string host, int port, int stream_id)
  {
    stream_error(result, 0);
    std::copy_n(
        host.c_str(),
        std::min(host.size(), sizeof(result->local_address) - 1),
        result->local_address);
    result->local_port = port;
    result->stream_id = stream_id;
  }

  std::pair<std::string, int>
  split_host_port(std::string data, std::string proto = "tcp")
  {
    std::string host, portStr;
    if (auto pos = data.find(":"); pos != std::string::npos)
    {
      host = data.substr(0, pos);
      portStr = data.substr(pos + 1);
    }
    else
      throw EINVAL;

    if (auto* serv = getservbyname(portStr.c_str(), proto.c_str()))
    {
      return {host, serv->s_port};
    }
    else
      return {host, std::stoi(portStr)};
  }

  int
  accept_port(const char* remote, uint16_t port, void* ptr)
  {
    (void)remote;
    if (port == *static_cast<uint16_t*>(ptr))
    {
      return 0;
    }
    return -1;
  }

}  // namespace

extern "C"
{
  struct lokinet_context*
  lokinet_default()
  {
    if (not g_context)
      g_context = std::make_unique<lokinet_context>();
    return g_context.get();
  }

  void
  lokinet_set_netid(const char* netid)
  {
    llarp::NetID::DefaultValue() = llarp::NetID{reinterpret_cast<const byte_t*>(netid)};
  }

  const char*
  lokinet_get_netid()
  {
    const auto netid = llarp::NetID::DefaultValue().ToString();
    return strdup(netid.c_str());
  }

  int
  lokinet_log_level(const char* level)
  {
    if (auto maybe = llarp::LogLevelFromString(level))
    {
      llarp::SetLogLevel(*maybe);
      return 0;
    }
    return -1;
  }

  char*
  lokinet_address(struct lokinet_context* ctx)
  {
    if (not ctx)
      return nullptr;
    auto lock = ctx->acquire();
    auto ep = ctx->endpoint();
    const auto addr = ep->GetIdentity().pub.Addr();
    const auto addrStr = addr.ToString();
    return strdup(addrStr.c_str());
  }

  int
  lokinet_add_bootstrap_rc(const char* data, size_t datalen, struct lokinet_context* ctx)
  {
    llarp_buffer_t buf{data, datalen};
    llarp::RouterContact rc{};
    if (ctx == nullptr)
      return -3;
    auto lock = ctx->acquire();
    // add a temp cryptography implementation here so rc.Verify works
    llarp::CryptoManager instance{new llarp::sodium::CryptoLibSodium{}};
    if (not rc.BDecode(&buf))
      return -1;
    if (not rc.Verify(llarp::time_now_ms()))
      return -2;
    ctx->config->bootstrap.routers.insert(std::move(rc));
    return 0;
  }

  struct lokinet_context*
  lokinet_context_new()
  {
    return new lokinet_context{};
  }

  void
  lokinet_context_free(struct lokinet_context* ctx)
  {
    lokinet_context_stop(ctx);
    delete ctx;
  }

  int
  lokinet_context_start(struct lokinet_context* ctx)
  {
    if (not ctx)
      return -1;
    auto lock = ctx->acquire();
    ctx->config->router.m_netId = lokinet_get_netid();
    ctx->config->logging.m_logLevel = llarp::GetLogLevel();
    ctx->runner = std::make_unique<std::thread>([ctx]() {
      llarp::util::SetThreadName("llarp-mainloop");
      ctx->impl->Configure(ctx->config);
      const llarp::RuntimeOptions opts{};
      try
      {
        ctx->impl->Setup(opts);
#ifdef SIG_PIPE
        signal(SIG_PIPE, SIGIGN);
#endif
        ctx->impl->Run(opts);
      }
      catch (std::exception& ex)
      {
        std::cerr << ex.what() << std::endl;
        ctx->impl->CloseAsync();
      }
    });
    while (not ctx->impl->IsUp())
    {
      if (ctx->impl->IsStopping())
        return -1;
      std::this_thread::sleep_for(50ms);
    }
    return 0;
  }

  int
  lokinet_wait_for_ready(int ms, struct lokinet_context* ctx)
  {
    if (ctx == nullptr)
      return -1;
    auto lock = ctx->acquire();
    auto ep = ctx->endpoint();
    int iterations = ms / 10;
    if (iterations <= 0)
    {
      ms = 10;
      iterations = 1;
    }
    while (not ep->IsReady() and iterations > 0)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{ms / 10});
      iterations--;
    }
    return ep->IsReady() ? 0 : -1;
  }

  void
  lokinet_context_stop(struct lokinet_context* ctx)
  {
    if (not ctx)
      return;
    auto lock = ctx->acquire();

    if (not ctx->impl->IsStopping())
    {
      ctx->impl->CloseAsync();
      ctx->impl->Wait();
    }

    if (ctx->runner)
      ctx->runner->join();

    ctx->runner.reset();
  }

  void
  lokinet_outbound_stream(
      struct lokinet_stream_result* result,
      const char* remote,
      const char* local,
      struct lokinet_context* ctx)
  {
    if (ctx == nullptr)
    {
      stream_error(result, EHOSTDOWN);
      return;
    }
    std::promise<void> promise;

    {
      auto lock = ctx->acquire();

      if (not ctx->impl->IsUp())
      {
        stream_error(result, EHOSTDOWN);
        return;
      }
      std::string remotehost;
      int remoteport;
      try
      {
        auto [h, p] = split_host_port(remote);
        remotehost = h;
        remoteport = p;
      }
      catch (int err)
      {
        stream_error(result, err);
        return;
      }
      // TODO: make configurable (?)
      std::string endpoint{"default"};

      llarp::SockAddr localAddr;
      try
      {
        if (local)
          localAddr = llarp::SockAddr{std::string{local}};
        else
          localAddr = llarp::SockAddr{"127.0.0.1:0"};
      }
      catch (std::exception& ex)
      {
        stream_error(result, EINVAL);
        return;
      }
      auto call = [&promise,
                   ctx,
                   result,
                   router = ctx->impl->router,
                   remotehost,
                   remoteport,
                   endpoint,
                   localAddr]() {
        auto ep = ctx->endpoint();
        if (ep == nullptr)
        {
          stream_error(result, ENOTSUP);
          promise.set_value();
          return;
        }
        auto* quic = ep->GetQUICTunnel();
        if (quic == nullptr)
        {
          stream_error(result, ENOTSUP);
          promise.set_value();
          return;
        }
        try
        {
          auto [addr, id] = quic->open(
              remotehost, remoteport, [](auto) {}, localAddr);
          auto [host, port] = split_host_port(addr.toString());
          ctx->outbound_stream(id);
          stream_okay(result, host, port, id);
        }
        catch (std::exception& ex)
        {
          std::cout << ex.what() << std::endl;
          stream_error(result, ECANCELED);
        }
        catch (int err)
        {
          stream_error(result, err);
        }
        promise.set_value();
      };

      ctx->impl->CallSafe([call]() {
        // we dont want the mainloop to die in case setting the value on the promise fails
        try
        {
          call();
        }
        catch (...)
        {}
      });
    }

    auto future = promise.get_future();
    try
    {
      if (auto status = future.wait_for(std::chrono::seconds{10});
          status == std::future_status::ready)
      {
        future.get();
      }
      else
      {
        stream_error(result, ETIMEDOUT);
      }
    }
    catch (std::exception& ex)
    {
      stream_error(result, EBADF);
    }
  }

  int
  lokinet_inbound_stream(uint16_t port, struct lokinet_context* ctx)
  {
    /// FIXME: delete pointer later
    return lokinet_inbound_stream_filter(&accept_port, (void*)new std::uintptr_t{port}, ctx);
  }

  int
  lokinet_inbound_stream_filter(
      lokinet_stream_filter acceptFilter, void* user, struct lokinet_context* ctx)
  {
    if (acceptFilter == nullptr)
    {
      acceptFilter = [](auto, auto, auto) { return 0; };
    }
    if (not ctx)
      return -1;
    std::promise<int> promise;
    {
      auto lock = ctx->acquire();
      if (not ctx->impl->IsUp())
      {
        return -1;
      }

      ctx->impl->CallSafe([ctx, acceptFilter, user, &promise]() {
        auto ep = ctx->endpoint();
        auto* quic = ep->GetQUICTunnel();
        auto id = quic->listen(
            [acceptFilter, user](auto remoteAddr, auto port) -> std::optional<llarp::SockAddr> {
              std::string remote{remoteAddr};
              if (auto result = acceptFilter(remote.c_str(), port, user))
              {
                if (result == -1)
                {
                  throw std::invalid_argument{"rejected"};
                }
              }
              else
                return llarp::SockAddr{"127.0.0.1:" + std::to_string(port)};
              return std::nullopt;
            });
        promise.set_value(id);
      });
    }
    auto ftr = promise.get_future();
    auto id = ftr.get();
    {
      auto lock = ctx->acquire();
      ctx->inbound_stream(id);
    }
    return id;
  }

  void
  lokinet_close_stream(int stream_id, struct lokinet_context* ctx)
  {
    if (not ctx)
      return;
    auto lock = ctx->acquire();
    if (not ctx->impl->IsUp())
      return;

    try
    {
      std::promise<void> promise;
      bool inbound = ctx->streams.at(stream_id);
      ctx->impl->CallSafe([stream_id, inbound, ctx, &promise]() {
        auto ep = ctx->endpoint();
        auto* quic = ep->GetQUICTunnel();
        try
        {
          if (inbound)
            quic->forget(stream_id);
          else
            quic->close(stream_id);
        }
        catch (...)
        {}
        promise.set_value();
      });
      promise.get_future().get();
    }
    catch (...)
    {}
  }
}