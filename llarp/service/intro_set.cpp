#include "intro_set.hpp"

#include <llarp/crypto/crypto.hpp>

#include <oxenc/bt_serialize.h>

namespace llarp::service
{
    static auto logcat = log::Cat("EncIntro");

    EncryptedIntroSet::EncryptedIntroSet(
        std::string signing_key,
        std::chrono::milliseconds signed_at,
        std::string enc_payload,
        std::string nonce,
        std::string s)
        : signed_at{signed_at},
          introset_payload{reinterpret_cast<uint8_t*>(enc_payload.data()), enc_payload.size()},
          nonce{reinterpret_cast<uint8_t*>(nonce.data())}
    {
        derived_signing_key.from_hex(signing_key);
        sig.from_string(std::move(s));
    }

    EncryptedIntroSet::EncryptedIntroSet(std::string bt_payload)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{bt_payload};
            bt_decode(btdc);
        }
        catch (...)
        {
            log::critical(logcat, "Error: EncryptedIntroSet failed to bt encode contents!");
        }
    }

    nlohmann::json EncryptedIntroSet::ExtractStatus() const
    {
        const auto sz = introset_payload.size();
        return {{"location", derived_signing_key.to_string()}, {"signedAt", to_json(signed_at)}, {"size", sz}};
    }

    bool EncryptedIntroSet::bt_decode(std::string_view buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};
            return bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "EncryptedIntroSet parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }
    }

    bool EncryptedIntroSet::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            derived_signing_key.from_string(btdc.require<std::string>("d"));
            nonce.from_string(btdc.require<std::string>("n"));
            signed_at = std::chrono::milliseconds{btdc.require<uint64_t>("s")};
            introset_payload = btdc.require<ustring>("x");
            sig.from_string(btdc.require<std::string>("z"));

            return true;
        }
        catch (...)
        {
            log::critical(logcat, "EncryptedIntroSet failed to decode bt payload!");
            throw;
        }
    }

    std::string EncryptedIntroSet::bt_encode() const
    {
        oxenc::bt_dict_producer btdp;

        try
        {
            btdp.append("d", derived_signing_key.to_view());
            btdp.append("n", nonce.to_view());
            btdp.append("s", signed_at.count());
            btdp.append(
                "x", std::string_view{reinterpret_cast<const char*>(introset_payload.data()), introset_payload.size()});
            btdp.append("z", sig.to_view());
        }
        catch (...)
        {
            log::critical(logcat, "Error: EncryptedIntroSet failed to bt encode contents!");
        }

        return std::move(btdp).str();
    }

    std::optional<EncryptedIntroSet> EncryptedIntroSet::construct(std::string bt)
    {
        if (EncryptedIntroSet ret; ret.bt_decode(std::move(bt)))
            return ret;

        return std::nullopt;
    }

    bool EncryptedIntroSet::other_is_newer(const EncryptedIntroSet& other) const
    {
        return signed_at < other.signed_at;
    }

    std::string EncryptedIntroSet::to_string() const
    {
        return fmt::format(
            "[EncIntroSet d={} n={} s={} x=[{} bytes] z={}]",
            derived_signing_key,
            nonce,
            signed_at.count(),
            introset_payload.size(),
            sig);
    }

    std::optional<IntroSet> EncryptedIntroSet::decrypt(const PubKey& root) const
    {
        std::optional<IntroSet> ret = std::nullopt;

        SharedSecret k(root);
        std::string payload{reinterpret_cast<const char*>(introset_payload.data()), introset_payload.size()};

        if (crypto::xchacha20(reinterpret_cast<uint8_t*>(payload.data()), payload.size(), k, nonce))
            ret = IntroSet{payload};

        return ret;
    }

    bool EncryptedIntroSet::is_expired(std::chrono::milliseconds now) const
    {
        return now >= signed_at + path::DEFAULT_LIFETIME;
    }

    bool EncryptedIntroSet::sign(const Ed25519Hash& k)
    {
        signed_at = llarp::time_now_ms();
        derived_signing_key = k.to_pubkey();
        sig.zero();
        auto bte = bt_encode();

        if (not crypto::sign(sig, k, reinterpret_cast<uint8_t*>(bte.data()), bte.size()))
            return false;

        log::debug(logcat, "Singed encrypted introset: {}", *this);
        return true;
    }

    bool EncryptedIntroSet::verify() const
    {
        if (is_expired())
            return false;

        EncryptedIntroSet copy(*this);
        copy.sig.zero();

        auto bte = copy.bt_encode();
        return crypto::verify(derived_signing_key, reinterpret_cast<uint8_t*>(bte.data()), bte.size(), sig);
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

    nlohmann::json IntroSet::ExtractStatus() const
    {
        nlohmann::json obj{{"published", to_json(time_signed)}};
        // TODO: this
        // std::vector<nlohmann::json> introsObjs;
        // std::transform(
        //     intros.begin(),
        //     intros.end(),
        //     std::back_inserter(introsObjs),
        //     [](const auto& intro) -> nlohmann::json { return intro.ExtractStatus(); });
        // obj["intros"] = introsObjs;
        // if (!topic.IsZero())
        //   obj["topic"] = topic.to_string();

        // std::vector<nlohmann::json> protocols;
        // std::transform(
        //     supported_protocols.begin(),
        //     supported_protocols.end(),
        //     std::back_inserter(protocols),
        //     [](const auto& proto) -> nlohmann::json { return service::to_string(proto); });
        // obj["protos"] = protocols;
        // std::vector<nlohmann::json> ranges;
        // std::transform(
        //     owned_ranges.begin(),
        //     owned_ranges.end(),
        //     std::back_inserter(ranges),
        //     [](const auto& range) -> nlohmann::json { return range.to_string(); });

        // obj["advertisedRanges"] = ranges;
        // if (exit_policy)
        //   obj["exitPolicy"] = exit_policy->ExtractStatus();

        return obj;
    }

    IntroSet::IntroSet(std::string bt_payload)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{bt_payload};
            bt_decode(btdc);
        }
        catch (...)
        {
            log::critical(logcat, "Error: EncryptedIntroSet failed to bt encode contents!");
        }
    }

    bool IntroSet::bt_decode(std::string_view buf)
    {
        try
        {
            oxenc::bt_dict_consumer btdc{buf};
            bt_decode(btdc);
        }
        catch (const std::exception& e)
        {
            // DISCUSS: rethrow or print warning/return false...?
            auto err = "IntroSet parsing exception: {}"_format(e.what());
            log::warning(logcat, "{}", err);
            throw std::runtime_error{err};
        }

        return true;
    }

    void IntroSet::bt_decode(oxenc::bt_dict_consumer& btdc)
    {
        try
        {
            {
                auto [key, subdict] = btdc.next_dict_consumer();

                if (key != "a")
                    throw std::invalid_argument{
                        "IntroSet received unexpected key (expected:'a', actual:{})"_format(key)};

                address_keys.bt_decode(subdict);
            }

            if (auto maybe_subdict = btdc.maybe<std::string>("e"); maybe_subdict)
            {
                oxenc::bt_dict_consumer subdict{*maybe_subdict};
                exit_policy->bt_decode(subdict);
            }

            {
                auto [key, sublist] = btdc.next_list_consumer();

                if (key != "i")
                    throw std::invalid_argument{
                        "IntroSet received unexpected key (expected:'i', actual:{})"_format(key)};

                while (not sublist.is_finished())
                {
                    intros.insert(sublist.consume_string());
                }
            }

            if (auto maybe_supportedprotos = btdc.maybe<std::string>("p"); maybe_supportedprotos)
            {
                oxenc::bt_list_consumer sublist{*maybe_supportedprotos};

                while (not sublist.is_finished())
                {
                    supported_protocols.push_back(ProtocolType{sublist.consume_integer<uint64_t>()});
                }
            }

            if (auto maybe_ownedranges = btdc.maybe<std::string>("i"); maybe_ownedranges)
            {
                oxenc::bt_list_consumer sublist{*maybe_ownedranges};

                while (not sublist.is_finished())
                {
                    _routed_ranges.emplace(sublist.consume_string());
                }
            }

            if (auto maybe_srvs = btdc.maybe<std::string>("s"); maybe_srvs)
            {
                oxenc::bt_list_consumer sublist{*maybe_srvs};

                while (not sublist.is_finished())
                {
                    SRVs.emplace_back(sublist.consume_string());
                }
            }

            time_signed = std::chrono::milliseconds{btdc.require<uint64_t>("t")};
            signature.from_string(btdc.require<std::string>("z"));
        }
        catch (...)
        {
            log::critical(logcat, "IntroSet failed to decode bt payload!");
            throw;
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

            if (not supported_protocols.empty())
            {
                auto sublist = btdp.append_list("p");
                for (auto& p : supported_protocols)
                    sublist.append(static_cast<uint64_t>(p));
            }

            if (not _routed_ranges.empty())
            {
                auto sublist = btdp.append_list("r");
                for (auto& r : _routed_ranges)
                    r.bt_encode(sublist);
            }

            if (not SRVs.empty())
            {
                auto sublist = btdp.append_list("s");
                for (auto& s : SRVs)
                    sublist.append(s.bt_encode());
            }

            btdp.append("t", time_signed.count());
            btdp.append("z", signature.to_view());
        }
        catch (...)
        {
            log::critical(logcat, "Error: IntroSet failed to bt encode contents!");
        }

        return std::move(btdp).str();
    }

    bool IntroSet::HasExpiredIntros(std::chrono::milliseconds now) const
    {
        for (const auto& intro : intros)
            if (now >= intro.expiry)
                return true;
        return false;
    }

    bool IntroSet::HasStaleIntros(std::chrono::milliseconds now, std::chrono::milliseconds delta) const
    {
        for (const auto& intro : intros)
            if (intro.expires_soon(delta, now))
                return true;
        return false;
    }

    bool IntroSet::IsExpired(std::chrono::milliseconds now) const
    {
        return GetNewestIntroExpiration() < now;
    }

    std::vector<llarp::dns::SRVData> IntroSet::GetMatchingSRVRecords(std::string_view service_proto) const
    {
        std::vector<llarp::dns::SRVData> records;

        for (const auto& srv : SRVs)
        {
            if (srv.service_proto == service_proto)
            {
                records.push_back(srv);
            }
        }

        return records;
    }

    bool IntroSet::verify(std::chrono::milliseconds now) const
    {
        IntroSet copy;
        copy = *this;
        copy.signature.zero();

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

    std::chrono::milliseconds IntroSet::GetNewestIntroExpiration() const
    {
        std::chrono::milliseconds maxTime = 0s;
        for (const auto& intro : intros)
            maxTime = std::max(intro.expiry, maxTime);
        return maxTime;
    }

    std::string IntroSet::to_string() const
    {
        return "[IntroSet addressKeys={} intros={{}} topic={} signedAt={} v={} sig={}]"_format(
            address_keys.to_string(),
            "{}"_format(fmt::join(intros, ",")),
            time_signed.count(),
            version,
            signature.to_view());
    }
}  // namespace llarp::service
