#pragma once
#include <llarp/crypto/crypto.hpp>
#include <llarp/ev/ev.hpp>

namespace llarp
{
    // forward declair
    struct Context;
    using Node_ptr = std::shared_ptr<llarp::Context>;

    namespace simulate
    {
        struct Simulation : public std::enable_shared_from_this<Simulation>
        {
            Simulation();

            llarp::CryptoManager m_CryptoManager;
            std::shared_ptr<EventLoop> m_NetLoop;

            std::unordered_map<std::string, Node_ptr> m_Nodes;

            void NodeUp(llarp::Context* node);

            Node_ptr AddNode(const std::string& name);

            void DelNode(const std::string& name);
        };

        using Sim_ptr = std::shared_ptr<Simulation>;
    }  // namespace simulate
}  // namespace llarp
