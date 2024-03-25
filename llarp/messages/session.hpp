#pragma once

#include "common.hpp"

#include <llarp/address/address.hpp>
#include <llarp/util/logging/buffer.hpp>

namespace llarp::session
{
    /** Fields for initiating sessions:
        - 'i' : ClientAddress of initiator
        - 's' : SessionTag for current session
        - 'x' : Authentication field
            - bt-encoded dict, values TBD
        - '' :
    */
    namespace Initiate
    {
        inline static std::string serialize(ClientAddress initiator, service::SessionTag tag)
        {
            oxenc::bt_dict_producer btdp;

            (void)initiator;
            (void)tag;

            try
            {
                //
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: InitiateSessionMessage failed to bt encode contents");
            }

            return std::move(btdp).str();
        };
    }  //  namespace Initiate

    /** Fields for setting a session tag:
     */
    namespace SetTag
    {
        inline static std::string serialize()
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                //
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: SetSessionTagMessage failed to bt encode contents");
            }

            return std::move(btdp).str();
        };
    }  //  namespace SetTag

    /** Fields for setting a session path:
     */
    namespace SetPath
    {
        inline static std::string serialize()
        {
            oxenc::bt_dict_producer btdp;

            try
            {
                //
            }
            catch (...)
            {
                log::error(messages::logcat, "Error: SetSessionPathMessage failed to bt encode contents");
            }

            return std::move(btdp).str();
        };
    }  // namespace SetPath

}  //  namespace llarp::session
