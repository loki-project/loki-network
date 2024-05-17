#include "sim_context.hpp"

#include <llarp.hpp>

namespace llarp
{
    namespace simulate
    {
        Simulation::Simulation() : m_CryptoManager(new sodium::CryptoLibSodium()) {}

        void Simulation::NodeUp(llarp::Context*) {}

        Node_ptr Simulation::AddNode(const std::string& name)
        {
            auto itr = m_Nodes.find(name);
            if (itr == m_Nodes.end())
            {
                itr = m_Nodes.emplace(name, std::make_shared<llarp::Context>(shared_from_this())).first;
            }
            return itr->second;
        }

        void Simulation::DelNode(const std::string& name)
        {
            m_Nodes.erase(name);
        }
    }  // namespace simulate
}  // namespace llarp
