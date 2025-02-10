#pragma once

#include <llarp.hpp>
#include <llarp/rpc/rpc_client.hpp>
#include <llarp/util/logging.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace omq = oxenmq;

namespace llarp::controller
{
    static auto logcat = log::Cat("rpc-controller");

    struct lokinet_instance
    {
      private:
        static size_t next_id;

      public:
        lokinet_instance() = delete;
        lokinet_instance(omq::ConnectionID c) : ID{++next_id}, cid{std::move(c)} {}

        const size_t ID;
        omq::ConnectionID cid;
    };

    struct rpc_controller
    {
        static std::shared_ptr<rpc_controller> make(omq::LogLevel level)
        {
            return std::shared_ptr<rpc_controller>{new rpc_controller{level}};
        }

      private:
        rpc_controller(omq::LogLevel level);

        std::shared_ptr<omq::OxenMQ> _omq;
        std::unordered_map<omq::address, lokinet_instance> _binds;
        std::map<size_t, omq::address> _indexes;

        void _initiate(omq::address src, std::string remote);
        void _status(omq::address src);
        void _close(omq::address src, std::string remote);

      public:
        bool omq_connect(const std::vector<std::string>& bind_addrs);

        bool start(std::vector<std::string>& bind_addrs);

        void list_all() const;

        void refresh();

        void initiate(size_t idx, std::string remote);

        void initiate(omq::address src, std::string remote);

        void status(omq::address src);

        void status(size_t idx);

        void close(omq::address src, std::string remote);

        void close(size_t idx, std::string remote);
    };
}  // namespace llarp::controller
