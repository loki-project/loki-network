#include "utils.hpp"

namespace llarp::controller
{
    size_t lokinet_instance::next_id = 0;

    static constexpr auto omq_cat_logger = [](omq::LogLevel lvl, const char* file, int line, std::string buf) {
        auto msg = "[{}:{}] {}"_format(file, line, buf);

        switch (lvl)
        {
            case oxenmq::LogLevel::fatal:
                log::critical(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::error:
                log::error(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::warn:
                log::warning(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::info:
                log::info(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::debug:
                log::debug(logcat, "{}", msg);
                break;
            case oxenmq::LogLevel::trace:
            default:
                log::trace(logcat, "{}", msg);
                break;
        }
    };

    rpc_controller::rpc_controller(omq::LogLevel level) : _omq{std::make_shared<omq::OxenMQ>(omq_cat_logger, level)} {}

    void rpc_controller::_initiate(omq::address src, std::string remote)
    {
        log::info(
            logcat,
            "Instructing lokinet instance (bind:{}) to initiate session to remote:{}",
            src.full_address(),
            remote);

        nlohmann::json req;
        req["pk"] = remote;
        req["x"] = false;

        if (auto it = _binds.find(src); it != _binds.end())
            _omq->request(
                it->second.cid,
                "llarp.session_init",
                [&](bool success, std::vector<std::string> data) {
                    if (success)
                    {
                        auto res = nlohmann::json::parse(data[0]);
                        log::info(logcat, "RPC call to initiate session succeeded: {}", res.dump());
                    }
                    else
                        log::critical(logcat, "RPC call to initiate session failed!");
                },
                req.dump());
        else
            log::critical(
                logcat, "Could not find connection ID to RPC bind {} for `session_init` command", src.full_address());
    }

    void rpc_controller::_status(omq::address src)
    {
        log::info(logcat, "Querying lokinet instance (bind:{}) for router status", src.full_address());

        if (auto it = _binds.find(src); it != _binds.end())
            _omq->request(it->second.cid, "llarp.status", [&](bool success, std::vector<std::string> data) {
                if (success)
                {
                    auto res = nlohmann::json::parse(data[0]);
                    log::info(logcat, "RPC call to query router status succeeded: \n{}\n", res.dump(4));
                }
                else
                    log::critical(logcat, "RPC call to query router status failed!");
            });
        else
            log::critical(
                logcat, "Could not find connection ID to RPC bind {} for `status` command", src.full_address());
    }

    void rpc_controller::_close(omq::address src, std::string remote)
    {
        log::info(
            logcat, "Querying lokinet instance (bind:{}) to close session to remote:{}", src.full_address(), remote);

        nlohmann::json req;
        req["pk"] = remote;

        if (auto it = _binds.find(src); it != _binds.end())
            _omq->request(
                it->second.cid,
                "llarp.session_close",
                [&](bool success, std::vector<std::string> data) {
                    if (success)
                    {
                        auto res = nlohmann::json::parse(data[0]);
                        log::info(logcat, "RPC call to close session succeeded: {}", res.dump());
                    }
                    else
                        log::critical(logcat, "RPC call to close session failed!");
                },
                req.dump());
        else
            log::critical(
                logcat, "Could not find connection ID to RPC bind {} for `session_close` command", src.full_address());
    }

    bool rpc_controller::omq_connect(const std::vector<std::string>& bind_addrs)
    {
        int i = 0;
        std::vector<std::promise<bool>> connect_proms{bind_addrs.size()};

        for (auto& b : bind_addrs)
        {
            omq::address bind{b};
            log::info(logcat, "RPC controller connecting to RPC bind address ({})", bind.full_address());

            auto cid = _omq->connect_remote(
                bind,
                [&, idx = i](auto) {
                    log::info(logcat, "Loki controller successfully connected to RPC bind ({})", bind.full_address());
                    connect_proms[idx].set_value(true);
                },
                [&, idx = i](auto, std::string_view msg) {
                    log::info(
                        logcat, "Loki controller failed to connect to RPC bind ({}): {}", bind.full_address(), msg);
                    connect_proms[idx].set_value(false);
                });
            auto it = _binds.emplace(bind, lokinet_instance{cid}).first;
            _indexes.emplace(it->second.ID, it->first);
            i += 1;
        }

        bool ret = true;

        for (auto& p : connect_proms)
            ret &= p.get_future().get();

        return ret;
    }

    bool rpc_controller::start(std::vector<std::string>& bind_addrs)
    {
        _omq->start();
        return omq_connect(bind_addrs);
    }

    void rpc_controller::list_all() const
    {
        auto msg = "\n\n\tLokinet RPC controller connected to {} RPC binds:\n"_format(_binds.size());
        for (auto& [idx, addr] : _indexes)
            msg += "\t\tID:{} | Address:{}\n"_format(idx, addr.full_address());

        log::info(logcat, "{}", msg);
    }

    void rpc_controller::refresh() { log::critical(logcat, "TODO: implement this!"); }

    void rpc_controller::initiate(size_t idx, std::string remote)
    {
        if (auto it = _indexes.find(idx); it != _indexes.end())
            _initiate(it->second, std::move(remote));
        else
            log::warning(logcat, "Could not find instance with given index: {}", idx);
    }

    void rpc_controller::initiate(omq::address src, std::string remote)
    {
        return _initiate(std::move(src), std::move(remote));
    }

    void rpc_controller::status(omq::address src) { return _status(std::move(src)); };

    void rpc_controller::status(size_t idx)
    {
        if (auto it = _indexes.find(idx); it != _indexes.end())
            _status(it->second);
        else
            log::warning(logcat, "Could not find instance with given index: {}", idx);
    }

    void rpc_controller::close(omq::address src, std::string remote)
    {
        return _close(std::move(src), std::move(remote));
    }

    void rpc_controller::close(size_t idx, std::string remote)
    {
        if (auto it = _indexes.find(idx); it != _indexes.end())
            _close(it->second, std::move(remote));
        else
            log::warning(logcat, "Could not find instance with given index: {}", idx);
    }
}  // namespace llarp::controller
