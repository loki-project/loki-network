#include "llarp_test.hpp"
#include "test_util.hpp"
#include <llarp/crypto/encrypted_frame.hpp>
#include <llarp/crypto/crypto.hpp>
#include <llarp/messages/relay_commit.hpp>
#include <catch2/catch.hpp>

using namespace ::llarp;

using EncryptedFrame = EncryptedFrame;
using SecretKey = SecretKey;
using PubKey = PubKey;
using LRCR = LR_CommitRecord;

class FrameTest
{
 public:
  FrameTest() : test::LlarpTest<>{}
  {
    crypto::encryption_keygen(alice);
    crypto::encryption_keygen(bob);
  }

  SecretKey alice, bob;
};

TEST_CASE_METHOD(FrameTest, "Frame crypto")
{
  EncryptedFrame f{256};
  f.Fill(0);
  LRCR record{};
  record.nextHop.Fill(1);
  record.tunnelNonce.Fill(2);
  record.rxid.Fill(3);
  record.txid.Fill(4);

  auto buf = f.Buffer();
  buf->cur = buf->base + EncryptedFrameOverheadSize;

  REQUIRE(record.BEncode(buf));

  // rewind buffer
  buf->cur = buf->base + EncryptedFrameOverheadSize;
  // encrypt to alice
  REQUIRE(f.EncryptInPlace(alice, bob.toPublic()));

  // decrypt from alice
  REQUIRE(f.DecryptInPlace(bob));

  LRCR otherRecord;
  REQUIRE(otherRecord.BDecode(buf));
  REQUIRE(otherRecord == record);
}
