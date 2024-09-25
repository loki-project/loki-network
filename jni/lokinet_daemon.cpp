#include "lokinet_jni_common.hpp"
#include "network_loki_lokinet_LokinetDaemon.h"

#include <llarp.hpp>
#include <llarp/config/config.hpp>
#include <llarp/router/router.hpp>

extern "C"
{
    JNIEXPORT jobject JNICALL Java_network_loki_lokinet_LokinetDaemon_Obtain(JNIEnv* env, jclass)
    {
        auto* ptr = new llarp::Context();
        if (ptr == nullptr)
            return nullptr;
        return env->NewDirectByteBuffer(ptr, sizeof(llarp::Context));
    }

    JNIEXPORT void JNICALL Java_network_loki_lokinet_LokinetDaemon_Free(JNIEnv* env, jclass, jobject buf)
    {
        auto ptr = FromBuffer<llarp::Context>(env, buf);
        delete ptr;
    }

    JNIEXPORT jboolean JNICALL
    Java_network_loki_lokinet_LokinetDaemon_Configure(JNIEnv* env, jobject self, jobject conf)
    {
        auto ptr = GetImpl<llarp::Context>(env, self);
        auto config = GetImpl<llarp::Config>(env, conf);
        if (ptr == nullptr || config == nullptr)
            return JNI_FALSE;
        try
        {
            llarp::RuntimeOptions opts{};

            // janky make_shared deep copy because jni + shared pointer = scary
            ptr->Configure(std::make_shared<llarp::Config>(*config));
            ptr->Setup(opts);
        }
        catch (...)
        {
            return JNI_FALSE;
        }
        return JNI_TRUE;
    }

    JNIEXPORT jint JNICALL Java_network_loki_lokinet_LokinetDaemon_Mainloop(JNIEnv* env, jobject self)
    {
        auto ptr = GetImpl<llarp::Context>(env, self);
        if (ptr == nullptr)
            return -1;
        llarp::RuntimeOptions opts{};
        return ptr->Run(opts);
    }

    JNIEXPORT jboolean JNICALL Java_network_loki_lokinet_LokinetDaemon_IsRunning(JNIEnv* env, jobject self)
    {
        auto ptr = GetImpl<llarp::Context>(env, self);
        return (ptr != nullptr && ptr->IsUp()) ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT jboolean JNICALL Java_network_loki_lokinet_LokinetDaemon_Stop(JNIEnv* env, jobject self)
    {
        auto ptr = GetImpl<llarp::Context>(env, self);
        if (ptr == nullptr)
            return JNI_FALSE;
        if (not ptr->IsUp())
            return JNI_FALSE;
        ptr->CloseAsync();
        ptr->Wait();
        return ptr->IsUp() ? JNI_FALSE : JNI_TRUE;
    }

    JNIEXPORT void JNICALL Java_network_loki_lokinet_LokinetDaemon_InjectVPNFD(JNIEnv* env, jobject self)
    {
        if (auto ptr = GetImpl<llarp::Context>(env, self))
            ptr->androidFD = GetObjectMemberAsInt<int>(env, self, "m_FD");
    }

    JNIEXPORT jint JNICALL Java_network_loki_lokinet_LokinetDaemon_GetUDPSocket(JNIEnv* env, jobject self)
    {
        if (auto ptr = GetImpl<llarp::Context>(env, self); ptr and ptr->router)
            return ptr->router->outbound_socket();
        return -1;
    }

    JNIEXPORT jstring JNICALL Java_network_loki_lokinet_LokinetDaemon_DetectFreeRange(JNIEnv* env, jclass)
    {
        std::string rangestr{};
        if (auto maybe = llarp::net::Platform::Default_ptr()->FindFreeRange())
        {
            rangestr = maybe->ToString();
        }
        return env->NewStringUTF(rangestr.c_str());
    }

    JNIEXPORT jstring JNICALL Java_network_loki_lokinet_LokinetDaemon_DumpStatus(JNIEnv* env, jobject self)
    {
        std::string status{};
        if (auto ptr = GetImpl<llarp::Context>(env, self))
        {
            if (ptr->IsUp())
            {
                std::promise<std::string> result;
                ptr->CallSafe([&result, router = ptr->router]() {
                    const auto status = router->ExtractStatus();
                    result.set_value(status.dump());
                });
                status = result.get_future().get();
            }
        }
        return env->NewStringUTF(status.c_str());
    }
}
