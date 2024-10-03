<<<<<<<< HEAD:llarp/contact/router_contact_local.cpp
#include "router_contact.hpp"
========
#include "relay_contact.hpp"
>>>>>>>> a41903e54 ((WIP, squash) contact library, re-org):llarp/contact/relay_contact_local.cpp

#include <oxenc/bt_serialize.h>

namespace llarp
{
    LocalRC LocalRC::make(Ed25519SecretKey secret, oxen::quic::Address local)
    {
        return *new LocalRC{std::move(secret), std::move(local)};
    }

    LocalRC::LocalRC(Ed25519SecretKey secret, oxen::quic::Address local) : _secret_key{std::move(secret)}
    {
        _router_id = seckey_to_pubkey(_secret_key);
        _addr = std::move(local);
        if (_addr.is_ipv6())
            _addr6.emplace(&_addr.in6());
        resign();
    }

    RemoteRC LocalRC::to_remote()
    {
        resign();
        return RemoteRC{view()};
    }

    void LocalRC::bt_sign(oxenc::bt_dict_producer& btdp)
    {
        _signature.clear();

        btdp.append_signature("~", [this](ustring_view to_sign) {
            std::array<unsigned char, 64> sig;

            if (!crypto::sign(const_cast<unsigned char*>(sig.data()), _secret_key, to_sign))
                throw std::runtime_error{"Failed to sign RC"};

            _signature = {sig.data(), sig.size()};
            return sig;
        });

        _payload = ustring{btdp.view<unsigned char>()};
    }

    void LocalRC::bt_encode(oxenc::bt_dict_producer& btdp)
    {
        btdp.append("", VERSION);

        std::array<unsigned char, 18> buf;

        {
            if (not _addr.is_ipv4())
                throw std::runtime_error{"Unable to encode RC: addr is not IPv4"};

            auto in4 = _addr.in4();

            std::memcpy(buf.data(), &in4.sin_addr.s_addr, 4);
            std::memcpy(buf.data() + 4, &in4.sin_port, 2);

            btdp.append("4", ustring_view{buf.data(), 6});
        }

        if (_addr6)
        {
            if (not _addr.is_ipv6())
                throw std::runtime_error{"Unable to encode RC: addr6 is set but is not IPv6"};

            auto in6 = _addr.in6();

            std::memcpy(buf.data(), &in6.sin6_addr.s6_addr, 16);
            std::memcpy(buf.data() + 16, &in6.sin6_port, 2);

            btdp.append("6", ustring_view{buf.data(), 18});
        }

        if (ACTIVE_NETID != llarp::LOKINET_DEFAULT_NETID)
            btdp.append("i", ACTIVE_NETID);

        btdp.append("p", _router_id.to_view());

        btdp.append("t", _timestamp.time_since_epoch().count());

        static_assert(llarp::LOKINET_VERSION.size() == 3);
        btdp.append("v", std::string_view{reinterpret_cast<const char*>(llarp::LOKINET_VERSION.data()), 3});
    }

    void LocalRC::resign()
    {
        set_systime_timestamp();
        oxenc::bt_dict_producer btdp;
        bt_encode(btdp);
        bt_sign(btdp);
    }
}  // namespace llarp
