#include <llarp/exit/exit_messages.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/crypto/crypto_libsodium.hpp>

#include <catch2/catch.hpp>

using namespace ::llarp;
using namespace ::llarp::test;

using ObtainExitMessage = routing::ObtainExitMessage;

void
fill(Signature& s)
{
  s.Fill(0xFF);
}

TEST_CASE("Sign-verify")
{
  SecretKey alice{};
  crypto::identity_keygen(alice);
  REQUIRE(not alice.IsZero());
  ObtainExitMessage msg{};
  msg.S = randint();
  msg.T = randint();
  CHECK(msg.Sign(alice));
  CHECK(msg.Verify());
  CHECK(msg.I == PubKey{seckey_topublic(alice)});
  CHECK(msg.version == llarp::constants::proto_version);
  CHECK_FALSE(msg.Z.IsZero());
}
