#include "catch2/catch.hpp"
#include <llarp/crypto/crypto.hpp>
#include <llarp/service/name.hpp>
#include <oxenc/hex.h>

using namespace std::literals;

TEST_CASE("Test LNS name decrypt", "[lns]")
{
  constexpr auto recordhex = "0ba76cbfdb6dc8f950da57ae781912f31c8ad0c55dbf86b88cb0391f563261a9656571a817be4092969f8a78ee0fcee260424acb4a1f4bbdd27348b71de006b6152dd04ed11bf3c4"sv;
  const auto recordbin = oxenc::from_hex(recordhex);
  CHECK(not recordbin.empty());
  llarp::SymmNonce n{};
  std::vector<byte_t> ciphertext{};
  const auto len = recordbin.size() - n.size();
  std::copy_n(recordbin.cbegin() + len, n.size(), n.data());
  std::copy_n(recordbin.cbegin(), len, std::back_inserter(ciphertext));
  const auto maybe = llarp::crypto::maybe_decrypt_name(std::string_view{reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size()}, n, "jason.loki");
  CHECK(maybe.has_value());
  const llarp::service::Address addr{*maybe};
  CHECK(addr.ToString() == "azfoj73snr9f3neh5c6sf7rtbaeabyxhr1m4un5aydsmsrxo964o.loki");
}


TEST_CASE("Test LNS validity", "[lns]")
{
  CHECK(not llarp::service::NameIsValid("loki.loki"));
  CHECK(not llarp::service::NameIsValid("snode.loki"));
  CHECK(not llarp::service::NameIsValid("localhost.loki"));
  CHECK(not llarp::service::NameIsValid("gayballs22.loki.loki"));
  CHECK(not llarp::service::NameIsValid("-loki.loki"));
  CHECK(not llarp::service::NameIsValid("super-mario-gayballs-.loki"));
  CHECK(not llarp::service::NameIsValid("bn--lolexdeeeeee.loki"));
  CHECK(not llarp::service::NameIsValid("2222222222a-.loki"));
  CHECK(not llarp::service::NameIsValid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.loki"));
  
  CHECK(llarp::service::NameIsValid("xn--animewasindeedamistake.loki"));
  CHECK(llarp::service::NameIsValid("memerionos.loki"));
  CHECK(llarp::service::NameIsValid("whyis.xn--animehorrible.loki"));
  CHECK(llarp::service::NameIsValid("the.goog.loki"));
  CHECK(llarp::service::NameIsValid("420.loki"));
}
