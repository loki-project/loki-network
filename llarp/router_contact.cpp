#include "router_contact.hpp"

#include "constants/version.hpp"
#include "crypto/crypto.hpp"
#include "net/net.hpp"
#include "util/bencode.hpp"
#include "util/buffer.hpp"
#include "util/logging.hpp"
#include "util/mem.hpp"
#include "util/time.hpp"

#include <oxenc/bt_serialize.h>

#include "util/file.hpp"

namespace llarp
{
  static auto logcat = log::Cat("RC");

  NetID&
  NetID::DefaultValue()
  {
    static NetID defaultID(reinterpret_cast<const byte_t*>(llarp::DEFAULT_NETID));
    return defaultID;
  }

  bool RouterContact::BlockBogons = true;

  /// 1 day rc lifespan
  constexpr auto rc_lifetime = 24h;
  /// an RC inserted long enough ago (4 hrs) is considered stale and is removed
  constexpr auto rc_stale_age = 4h;
  /// window of time in which a router wil try to update their RC before it is marked stale
  constexpr auto rc_update_window = 5min;
  /// update RCs shortly before they are about to expire
  constexpr auto rc_update_interval = rc_stale_age - rc_update_window;

  llarp_time_t RouterContact::Lifetime = rc_lifetime;
  llarp_time_t RouterContact::StaleInsertionAge = rc_stale_age;
  llarp_time_t RouterContact::UpdateInterval = rc_update_interval;

  /// how many rc lifetime intervals should we wait until purging an rc
  constexpr auto expiration_lifetime_generations = 10;
  /// the max age of an rc before we want to expire it
  constexpr auto rc_expire_age = rc_lifetime * expiration_lifetime_generations;

  NetID::NetID(const byte_t* val)
  {
    const size_t len = strnlen(reinterpret_cast<const char*>(val), size());
    std::copy(val, val + len, begin());
  }

  NetID::NetID() : NetID(DefaultValue().data())
  {}

  bool
  NetID::operator==(const NetID& other) const
  {
    return ToString() == other.ToString();
  }

  std::string
  NetID::ToString() const
  {
    return {begin(), std::find(begin(), end(), '\0')};
  }

  bool
  NetID::BDecode(llarp_buffer_t* buf)
  {
    Zero();
    llarp_buffer_t strbuf;
    if (!bencode_read_string(buf, &strbuf))
      return false;

    if (strbuf.sz > size())
      return false;

    std::copy(strbuf.base, strbuf.base + strbuf.sz, begin());
    return true;
  }

  bool
  NetID::BEncode(llarp_buffer_t* buf) const
  {
    auto term = std::find(begin(), end(), '\0');
    return bencode_write_bytestring(buf, data(), std::distance(begin(), term));
  }

  bool
  RouterContact::BEncode(llarp_buffer_t* buf) const
  {
    if (version == 0)
      return BEncodeSignedSection(buf);
    else if (version == 1)
    {
      // TODO: heapless serialization for this in lokimq's bt serialization.
      if (not buf->writef("li1e%zu:", signature.size()))
        return false;
      if (not buf->write(signature.begin(), signature.end()))
        return false;
      if (not buf->write(signed_bt_dict.begin(), signed_bt_dict.end()))
        return false;
      if (not buf->writef("e"))
        return false;

      return true;
    }

    return false;
  }

  std::string
  RouterContact::ToTXTRecord() const
  {
    std::string result;
    auto out = std::back_inserter(result);
    for (const auto& addr : addrs)
      fmt::format_to(out, "ai_addr={}; ai_pk={}; ", addr.toIpAddress(), addr.pubkey);
    fmt::format_to(out, "updated={}; onion_pk={}; ", last_updated.count(), enckey.ToHex());
    if (routerVersion.has_value())
      fmt::format_to(out, "router_version={}; ", *routerVersion);
    return result;
  }

  bool
  RouterContact::FromOurNetwork() const
  {
    return netID == NetID::DefaultValue();
  }

  bool
  RouterContact::BEncodeSignedSection(llarp_buffer_t* buf) const
  {
    /* write dict begin */
    if (!bencode_start_dict(buf))
      return false;

    /* write ai if they exist */
    if (!bencode_write_bytestring(buf, "a", 1))
      return false;
    if (!BEncodeWriteList(addrs.begin(), addrs.end(), buf))
      return false;

    /* write netid */
    if (!bencode_write_bytestring(buf, "i", 1))
      return false;
    if (!netID.BEncode(buf))
      return false;
    /* write signing pubkey */
    if (!bencode_write_bytestring(buf, "k", 1))
      return false;
    if (!pubkey.BEncode(buf))
      return false;

    std::string nick = Nick();
    if (!nick.empty())
    {
      /* write nickname */
      if (!bencode_write_bytestring(buf, "n", 1))
      {
        return false;
      }
      if (!bencode_write_bytestring(buf, nick.c_str(), nick.size()))
      {
        return false;
      }
    }

    /* write encryption pubkey */
    if (!bencode_write_bytestring(buf, "p", 1))
      return false;
    if (!enckey.BEncode(buf))
      return false;

    // write router version if present
    if (routerVersion)
    {
      if (not BEncodeWriteDictEntry("r", *routerVersion, buf))
        return false;
    }

    if (version > 0)
    {
      // srv records if present
      if (not BEncodeWriteDictList("s", srvRecords, buf))
        return false;
    }
    /* write last updated */
    if (!bencode_write_bytestring(buf, "u", 1))
      return false;
    if (!bencode_write_uint64(buf, last_updated.count()))
      return false;

    /* write versions */
    if (!bencode_write_uint64_entry(buf, "v", 1, version))
      return false;

    if (serializeExit)
    {
      /* write xi if they exist */
      if (!bencode_write_bytestring(buf, "x", 1))
        return false;
      /* no exits anymore in RCs */
      const std::vector<AlignedBuffer<8>> exits{};
      if (!BEncodeWriteList(exits.begin(), exits.end(), buf))
        return false;
    }

    if (version == 0)
    {
      /* write signature */
      if (!bencode_write_bytestring(buf, "z", 1))
        return false;
      if (!signature.BEncode(buf))
        return false;
    }

    return bencode_end(buf);
  }

  void
  RouterContact::Clear()
  {
    addrs.clear();
    signature.Zero();
    nickname.Zero();
    enckey.Zero();
    pubkey.Zero();
    routerVersion = std::optional<RouterVersion>{};
    last_updated = 0s;
    srvRecords.clear();
    version = llarp::constants::proto_version;
  }

  util::StatusObject
  RouterContact::ExtractStatus() const
  {
    util::StatusObject obj{
        {"lastUpdated", last_updated.count()},
        {"publicRouter", IsPublicRouter()},
        {"identity", pubkey.ToString()},
        {"addresses", addrs}};

    if (HasNick())
    {
      obj["nickname"] = Nick();
    }
    if (routerVersion)
    {
      obj["routerVersion"] = routerVersion->ToString();
    }
    std::vector<util::StatusObject> srv;
    for (const auto& record : srvRecords)
    {
      srv.emplace_back(record.ExtractStatus());
    }
    obj["srvRecords"] = srv;
    return obj;
  }

  bool
  RouterContact::BDecode(llarp_buffer_t* buf)
  {
    Clear();

    if (*buf->cur == 'd')  // old format
    {
      return DecodeVersion_0(buf);
    }
    else if (*buf->cur != 'l')  // if not dict, should be new format and start with list
    {
      return false;
    }

    try
    {
      std::string_view buf_view(reinterpret_cast<char*>(buf->cur), buf->size_left());
      oxenc::bt_list_consumer btlist(buf_view);

      uint64_t outer_version = btlist.consume_integer<uint64_t>();

      if (outer_version == 1)
      {
        bool decode_result = DecodeVersion_1(btlist);

        // Abuse bt_list_consumer to grab a reference to its protected `data` string_view, which is
        // the first member and so at the beginning of the struct.  This is horrible (thanks to the
        // disaster known as llarp_buffer_t), and is going away in the in-progress lokinet rewrite.
        auto& btlist_data = *reinterpret_cast<std::string_view*>(&btlist);

        // advance the llarp_buffer_t since lokimq serialization is unaware of it.
        buf->cur += btlist_data.data() - buf_view.data() + 1;

        return decode_result;
      }
      else
      {
        log::warning(logcat, "Received RouterContact with unkown version ({})", outer_version);
        return false;
      }
    }
    catch (const std::exception& e)
    {
      log::debug(logcat, "RouterContact::BDecode failed: {}", e.what());
    }

    return false;
  }

  bool
  RouterContact::DecodeVersion_0(llarp_buffer_t* buf)
  {
    return bencode_decode_dict(*this, buf);
  }

  bool
  RouterContact::DecodeVersion_1(oxenc::bt_list_consumer& btlist)
  {
    auto signature_string = btlist.consume_string_view();
    signed_bt_dict = btlist.consume_dict_data();

    if (not btlist.is_finished())
    {
      log::debug(logcat, "RouterContact serialized list too long for specified version.");
      return false;
    }

    llarp_buffer_t sigbuf(signature_string.data(), signature_string.size());
    if (not signature.FromBytestring(&sigbuf))
    {
      log::debug(logcat, "RouterContact serialized signature had invalid length.");
      return false;
    }

    llarp_buffer_t data_dict_buf(signed_bt_dict.data(), signed_bt_dict.size());
    return bencode_decode_dict(*this, &data_dict_buf);
  }

  bool
  RouterContact::DecodeKey(const llarp_buffer_t& key, llarp_buffer_t* buf)
  {
    bool read = false;
    if (!BEncodeMaybeReadDictList("a", addrs, read, key, buf))
      return false;

    if (!BEncodeMaybeReadDictEntry("i", netID, read, key, buf))
      return false;

    if (!BEncodeMaybeReadDictEntry("k", pubkey, read, key, buf))
      return false;

    if (key.startswith("r"))
    {
      RouterVersion r;
      if (not r.BDecode(buf))
        return false;
      routerVersion = r;
      return true;
    }

    if (key.startswith("n"))
    {
      llarp_buffer_t strbuf;
      if (!bencode_read_string(buf, &strbuf))
      {
        return false;
      }
      if (strbuf.sz > llarp::AlignedBuffer<(32)>::size())
      {
        return false;
      }
      nickname.Zero();
      std::copy(strbuf.base, strbuf.base + strbuf.sz, nickname.begin());
      return true;
    }

    if (not BEncodeMaybeReadDictList("s", srvRecords, read, key, buf))
      return false;

    if (!BEncodeMaybeReadDictEntry("p", enckey, read, key, buf))
      return false;

    if (!BEncodeMaybeReadDictInt("u", last_updated, read, key, buf))
      return false;

    if (!BEncodeMaybeReadDictInt("v", version, read, key, buf))
      return false;

    if (key.startswith("x") and serializeExit)
    {
      return bencode_discard(buf);
    }

    if (!BEncodeMaybeReadDictEntry("z", signature, read, key, buf))
      return false;

    return read or bencode_discard(buf);
  }

  bool
  RouterContact::IsPublicRouter() const
  {
    if (not routerVersion)
      return false;
    return !addrs.empty();
  }

  bool
  RouterContact::HasNick() const
  {
    return nickname[0] != 0;
  }

  void
  RouterContact::SetNick(std::string_view nick)
  {
    nickname.Zero();
    std::copy(
        nick.begin(), nick.begin() + std::min(nick.size(), nickname.size()), nickname.begin());
  }

  bool
  RouterContact::IsExpired(llarp_time_t now) const
  {
    return Age(now) >= rc_expire_age;
  }

  llarp_time_t
  RouterContact::TimeUntilExpires(llarp_time_t now) const
  {
    const auto expiresAt = last_updated + Lifetime;
    return now < expiresAt ? expiresAt - now : 0s;
  }

  llarp_time_t
  RouterContact::Age(llarp_time_t now) const
  {
    return now > last_updated ? now - last_updated : 0s;
  }

  bool
  RouterContact::ExpiresSoon(llarp_time_t now, llarp_time_t dlt) const
  {
    return TimeUntilExpires(now) <= dlt;
  }

  std::string
  RouterContact::Nick() const
  {
    auto term = std::find(nickname.begin(), nickname.end(), '\0');
    return std::string(nickname.begin(), term);
  }

  bool
  RouterContact::Sign(const SecretKey& secretkey)
  {
    pubkey = llarp::seckey_topublic(secretkey);
    std::array<byte_t, MAX_RC_SIZE> tmp;
    llarp_buffer_t buf(tmp);
    signature.Zero();
    last_updated = time_now_ms();

    if (!BEncodeSignedSection(&buf))
    {
      return false;
    }
    buf.sz = buf.cur - buf.base;
    buf.cur = buf.base;

    signed_bt_dict = std::string(reinterpret_cast<char*>(buf.base), buf.sz);

    if (version == 0 or version == 1)
    {
      return CryptoManager::instance()->sign(signature, secretkey, buf);
    }

    return false;
  }

  bool
  RouterContact::Verify(llarp_time_t now, bool allowExpired) const
  {
    if (netID != NetID::DefaultValue())
    {
      log::error(
          logcat, "netid mismatch: '{}' (theirs) != '{}' (ours)", netID, NetID::DefaultValue());
      return false;
    }

    if (IsExpired(now) and not allowExpired)
      return false;

    // TODO: make net* overridable
    const auto* net = net::Platform::Default_ptr();
    for (const auto& a : addrs)
    {
      if (net->IsBogon(a.ip) && BlockBogons)
      {
        log::error(logcat, "invalid address info: {}", a);
        return false;
      }
    }
    if (!VerifySignature())
    {
      log::error(logcat, "invalid signature: {}", *this);
      return false;
    }
    return true;
  }

  bool
  RouterContact::VerifySignature() const
  {
    if (version == 0)
    {
      RouterContact copy;
      copy = *this;
      copy.signature.Zero();
      std::array<byte_t, MAX_RC_SIZE> tmp;
      llarp_buffer_t buf(tmp);
      if (!copy.BEncode(&buf))
      {
        log::error(logcat, "bencode failed");
        return false;
      }
      buf.sz = buf.cur - buf.base;
      buf.cur = buf.base;
      return CryptoManager::instance()->verify(pubkey, buf, signature);
    }
    /* else */
    if (version == 1)
    {
      llarp_buffer_t buf{signed_bt_dict};
      return CryptoManager::instance()->verify(pubkey, buf, signature);
    }

    return false;
  }

  static constexpr std::array obsolete_bootstraps = {
      "7a16ac0b85290bcf69b2f3b52456d7e989ac8913b4afbb980614e249a3723218"sv,
      "e6b3a6fe5e32c379b64212c72232d65b0b88ddf9bbaed4997409d329f8519e0b"sv,
  };

  bool
  RouterContact::IsObsoleteBootstrap() const
  {
    for (const auto& k : obsolete_bootstraps)
    {
      if (pubkey.ToHex() == k)
        return true;
    }
    return false;
  }

  bool
  RouterContact::Write(const fs::path& fname) const
  {
    std::array<byte_t, MAX_RC_SIZE> tmp;
    llarp_buffer_t buf(tmp);
    if (!BEncode(&buf))
    {
      return false;
    }
    try
    {
      util::dump_file(fname, tmp.data(), buf.cur - buf.base);
    }
    catch (const std::exception& e)
    {
      log::error(logcat, "Failed to write RC to {}: {}", fname, e.what());
      return false;
    }
    return true;
  }

  bool
  RouterContact::Read(const fs::path& fname)
  {
    std::array<byte_t, MAX_RC_SIZE> tmp;
    llarp_buffer_t buf(tmp);
    try
    {
      util::slurp_file(fname, tmp.data(), tmp.size());
    }
    catch (const std::exception& e)
    {
      log::error(logcat, "Failed to read RC from {}: {}", fname, e.what());
      return false;
    }
    return BDecode(&buf);
  }

  std::string
  RouterContact::ToString() const
  {
    return fmt::format(
        "[RC k={} updated={} netid={} v={} ai={{{}}} e={} z={}]",
        pubkey,
        last_updated.count(),
        netID,
        version,
        fmt::format("{}", fmt::join(addrs, ",")),
        enckey,
        signature);
  }

}  // namespace llarp
