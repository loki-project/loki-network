#include "intro_set.hpp"

#include <llarp/crypto/crypto.hpp>

#include <oxenc/bt_serialize.h>

namespace llarp::service
{
    EncryptedIntroSet::EncryptedIntroSet(
        std::string signing_key,
        std::chrono::milliseconds signed_at,
        std::string enc_payload,
        std::string nonce,
        std::string s)
        : signedAt{signed_at},
          introsetPayload{reinterpret_cast<uint8_t*>(enc_payload.data()), enc_payload.size()},
          nonce{reinterpret_cast<uint8_t*>(nonce.data())}
    {
        derivedSigningKey = PubKey::make_from_hex(signing_key);
        sig.from_string(std::move(s));
    }

    EncryptedIntroSet::EncryptedIntroSet(std::string bt_payload)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{bt_payload};

            derivedSigningKey = PubKey::make_from_hex(btdc.require<std::string>("d"));
            nonce.from_string(btdc.require<std::string>("n"));
            signedAt = std::chrono::milliseconds{btdc.require<uint64_t>("s")};
            introsetPayload = btdc.require<ustring>("x");
            sig.from_string(btdc.require<std::string>("z"));
        }
        catch (...)
        {
            log::critical(net_cat, "Error: EncryptedIntroSet failed to bt encode contents!");
        }
    }

    StatusObject EncryptedIntroSet::ExtractStatus() const
    {
        const auto sz = introsetPayload.size();
        return {{"location", derivedSigningKey.to_string()}, {"signedAt", to_json(signedAt)}, {"size", sz}};
    }

    std::string EncryptedIntroSet::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        try
        {
            btdp.append("d", derivedSigningKey.ToView());
            btdp.append("n", nonce.ToView());
            btdp.append("s", signedAt.count());
            btdp.append(
                "x", std::string_view{reinterpret_cast<const char*>(introsetPayload.data()), introsetPayload.size()});
            btdp.append("z", sig.ToView());
        }
        catch (...)
        {
            log::critical(net_cat, "Error: EncryptedIntroSet failed to bt encode contents!");
        }

        return std::move(btdp).str();
    }

    bool EncryptedIntroSet::decode_key(const llarp_buffer_t& key, llarp_buffer_t* buf)
    {
        bool read = false;
        if (key.startswith("x"))
        {
            llarp_buffer_t strbuf;
            if (not bencode_read_string(buf, &strbuf))
                return false;
            if (strbuf.sz > MAX_INTROSET_SIZE)
                return false;
            introsetPayload.resize(strbuf.sz);
            std::copy_n(strbuf.base, strbuf.sz, introsetPayload.data());
            return true;
        }
        if (not BEncodeMaybeReadDictEntry("d", derivedSigningKey, read, key, buf))
            return false;

        if (not BEncodeMaybeReadDictEntry("n", nonce, read, key, buf))
            return false;

        if (not BEncodeMaybeReadDictInt("s", signedAt, read, key, buf))
            return false;

        if (not BEncodeMaybeReadDictEntry("z", sig, read, key, buf))
            return false;
        return read;
    }

    bool EncryptedIntroSet::OtherIsNewer(const EncryptedIntroSet& other) const
    {
        return signedAt < other.signedAt;
    }

    std::string EncryptedIntroSet::to_string() const
    {
        return fmt::format(
            "[EncIntroSet d={} n={} s={} x=[{} bytes] z={}]",
            derivedSigningKey,
            nonce,
            signedAt.count(),
            introsetPayload.size(),
            sig);
    }

    IntroSet EncryptedIntroSet::decrypt(const PubKey& root) const
    {
        SharedSecret k(root);
        std::string payload{reinterpret_cast<const char*>(introsetPayload.data()), introsetPayload.size()};

        crypto::xchacha20(reinterpret_cast<uint8_t*>(payload.data()), payload.size(), k, nonce);

        return IntroSet{payload};
    }

    bool EncryptedIntroSet::IsExpired(llarp_time_t now) const
    {
        return now >= signedAt + path::DEFAULT_LIFETIME;
    }

    bool EncryptedIntroSet::Sign(const PrivateKey& k)
    {
        signedAt = llarp::time_now_ms();
        if (not k.to_pubkey(derivedSigningKey))
            return false;
        sig.Zero();
        auto bte = bt_encode();

        if (not crypto::sign(sig, k, reinterpret_cast<uint8_t*>(bte.data()), bte.size()))
            return false;
        LogDebug("signed encrypted introset: ", *this);
        return true;
    }

    bool EncryptedIntroSet::verify(llarp_time_t now) const
    {
        if (IsExpired(now))
            return false;

        EncryptedIntroSet copy(*this);
        copy.sig.Zero();

        auto bte = copy.bt_encode();
        return crypto::verify(derivedSigningKey, reinterpret_cast<uint8_t*>(bte.data()), bte.size(), sig);
    }

    bool EncryptedIntroSet::verify(uint8_t* introset, size_t introset_size, uint8_t* key, uint8_t* sig)
    {
        return crypto::verify(key, introset, introset_size, sig);
    }

    bool EncryptedIntroSet::verify(std::string introset, std::string key, std::string sig)
    {
        return crypto::verify(
            reinterpret_cast<uint8_t*>(key.data()),
            reinterpret_cast<uint8_t*>(introset.data()),
            introset.size(),
            reinterpret_cast<uint8_t*>(sig.data()));
    }

    StatusObject IntroSet::ExtractStatus() const
    {
        StatusObject obj{{"published", to_json(time_signed)}};
        // TODO: this
        // std::vector<StatusObject> introsObjs;
        // std::transform(
        //     intros.begin(),
        //     intros.end(),
        //     std::back_inserter(introsObjs),
        //     [](const auto& intro) -> StatusObject { return intro.ExtractStatus(); });
        // obj["intros"] = introsObjs;
        // if (!topic.IsZero())
        //   obj["topic"] = topic.to_string();

        // std::vector<StatusObject> protocols;
        // std::transform(
        //     supported_protocols.begin(),
        //     supported_protocols.end(),
        //     std::back_inserter(protocols),
        //     [](const auto& proto) -> StatusObject { return service::to_string(proto); });
        // obj["protos"] = protocols;
        // std::vector<StatusObject> ranges;
        // std::transform(
        //     owned_ranges.begin(),
        //     owned_ranges.end(),
        //     std::back_inserter(ranges),
        //     [](const auto& range) -> StatusObject { return range.to_string(); });

        // obj["advertisedRanges"] = ranges;
        // if (exit_policy)
        //   obj["exitPolicy"] = exit_policy->ExtractStatus();

        return obj;
    }

    bool IntroSet::decode_key(const llarp_buffer_t& key, llarp_buffer_t* buf)
    {
        bool read = false;
        if (!BEncodeMaybeReadDictEntry("a", address_keys, read, key, buf))
            return false;

        if (key.startswith("e"))
        {
            net::TrafficPolicy policy;
            if (not policy.BDecode(buf))
                return false;
            exit_policy = policy;
            return true;
        }

        if (key.startswith("i"))
        {
            return BEncodeReadList(intros, buf);
        }
        if (!BEncodeMaybeReadDictEntry("k", sntru_pubkey, read, key, buf))
            return false;

        if (key.startswith("p"))
        {
            return bencode_read_list(
                [&](llarp_buffer_t* buf, bool more) {
                    if (more)
                    {
                        uint64_t protoval;
                        if (not bencode_read_integer(buf, &protoval))
                            return false;
                        supported_protocols.emplace_back(static_cast<ProtocolType>(protoval));
                    }
                    return true;
                },
                buf);
        }

        if (key.startswith("r"))
        {
            return BEncodeReadSet(owned_ranges, buf);
        }

        if (key.startswith("s"))
        {
            uint8_t* begin = buf->cur;
            if (not bencode_discard(buf))
                return false;

            uint8_t* end = buf->cur;

            std::string_view srvString(reinterpret_cast<const char*>(begin), static_cast<size_t>(end - begin));

            try
            {
                oxenc::bt_deserialize(srvString, SRVs);
            }
            catch (const oxenc::bt_deserialize_invalid& err)
            {
                LogError("Error decoding SRV records from IntroSet: ", err.what());
                return false;
            }
            read = true;
        }

        if (!BEncodeMaybeReadDictInt("t", time_signed, read, key, buf))
            return false;

        if (!BEncodeMaybeReadDictInt("v", version, read, key, buf))
            return false;

        if (!BEncodeMaybeReadDictEntry("z", signature, read, key, buf))
            return false;

        return read or bencode_discard(buf);
    }

    IntroSet::IntroSet(std::string bt_payload)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{bt_payload};

            if (btdc.key() == "a")
            {
                auto subdict = btdc.consume_dict_consumer();
                address_keys.bt_decode(subdict);
            }

            if (btdc.key() == "e")
            {
                auto subdict = btdc.consume_dict_consumer();
                exit_policy->bt_decode(subdict);
            }

            if (btdc.key() == "i")
            {
                auto sublist = btdc.consume_list_consumer();
                while (not sublist.is_finished())
                {
                    intros.emplace_back(sublist.consume_string());
                }
            }

            sntru_pubkey.from_string(btdc.require<std::string>("k"));

            if (btdc.key() == "p")
            {
                auto sublist = btdc.consume_list_consumer();
                while (not sublist.is_finished())
                {
                    supported_protocols.emplace_back(ProtocolType{sublist.consume_integer<uint64_t>()});
                }
            }

            if (btdc.key() == "r")
            {
                auto sublist = btdc.consume_list_consumer();
                while (not sublist.is_finished())
                {
                    owned_ranges.emplace(sublist.consume_string());
                }
            }

            if (btdc.key() == "s")
            {
                // TODO: fuck everything about these tuples
                // auto sublist = btdc.consume_list_consumer();
                // while (not sublist.is_finished())
                // {
                //   // auto s = oxenc::
                //   auto sd = SRVs.emplace_back();

                // }
            }

            time_signed = std::chrono::milliseconds{btdc.require<uint64_t>("t")};
            signature.from_string(btdc.require<std::string>("z"));
        }
        catch (...)
        {
            log::critical(net_cat, "Error: EncryptedIntroSet failed to bt encode contents!");
        }
    }

    std::string IntroSet::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        try
        {
            {
                auto subdict = btdp.append_dict("a");
                address_keys.bt_encode(subdict);
            }

            if (exit_policy)
            {
                auto subdict = btdp.append_dict("e");
                exit_policy->bt_encode(subdict);
            }

            {
                auto sublist = btdp.append_list("i");
                for (auto& i : intros)
                    i.bt_encode(sublist);
            }

            btdp.append("k", sntru_pubkey.ToView());

            if (not supported_protocols.empty())
            {
                auto sublist = btdp.append_list("p");
                for (auto& p : supported_protocols)
                    sublist.append(static_cast<uint64_t>(p));
            }

            if (not owned_ranges.empty())
            {
                auto sublist = btdp.append_list("r");
                for (auto& r : owned_ranges)
                    r.bt_encode(sublist);
            }

            if (not SRVs.empty())
            {
                auto sublist = btdp.append_list("s");
                for (auto& s : SRVs)
                    sublist.append(oxenc::bt_serialize(s));
            }

            btdp.append("t", time_signed.count());
            btdp.append("z", signature.ToView());
        }
        catch (...)
        {
            log::critical(net_cat, "Error: IntroSet failed to bt encode contents!");
        }

        return std::move(btdp).str();
    }

    bool IntroSet::HasExpiredIntros(llarp_time_t now) const
    {
        for (const auto& intro : intros)
            if (now >= intro.expiry)
                return true;
        return false;
    }

    bool IntroSet::HasStaleIntros(llarp_time_t now, llarp_time_t delta) const
    {
        for (const auto& intro : intros)
            if (intro.ExpiresSoon(now, delta))
                return true;
        return false;
    }

    bool IntroSet::IsExpired(llarp_time_t now) const
    {
        return GetNewestIntroExpiration() < now;
    }

    std::vector<llarp::dns::SRVData> IntroSet::GetMatchingSRVRecords(std::string_view service_proto) const
    {
        std::vector<llarp::dns::SRVData> records;

        for (const auto& tuple : SRVs)
        {
            if (std::get<0>(tuple) == service_proto)
            {
                records.push_back(llarp::dns::SRVData::fromTuple(tuple));
            }
        }

        return records;
    }

    bool IntroSet::verify(llarp_time_t now) const
    {
        IntroSet copy;
        copy = *this;
        copy.signature.Zero();

        auto bte = copy.bt_encode();

        if (!address_keys.verify(reinterpret_cast<uint8_t*>(bte.data()), bte.size(), signature))
        {
            return false;
        }
        // valid timestamps
        // add max clock skew
        now += MAX_INTROSET_TIME_DELTA;
        for (const auto& intro : intros)
        {
            if (intro.expiry > now && intro.expiry - now > path::DEFAULT_LIFETIME)
            {
                return false;
            }
        }
        return not IsExpired(now);
    }

    llarp_time_t IntroSet::GetNewestIntroExpiration() const
    {
        llarp_time_t maxTime = 0s;
        for (const auto& intro : intros)
            maxTime = std::max(intro.expiry, maxTime);
        return maxTime;
    }

    std::string IntroSet::to_string() const
    {
        return fmt::format(
            "[IntroSet addressKeys={} intros={{{}}} sntrupKey={} topic={} signedAt={} v={} sig={}]",
            address_keys,
            fmt::format("{}", fmt::join(intros, ",")),
            sntru_pubkey,
            time_signed.count(),
            version,
            signature);
    }
}  // namespace llarp::service
