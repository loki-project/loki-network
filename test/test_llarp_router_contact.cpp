#include <catch2/catch.hpp>

#include <llarp/crypto/crypto.hpp>
#include <llarp/router_contact.hpp>
#include <llarp/net/net_int.hpp>
#include <llarp/util/time.hpp>

namespace llarp
{

TEST_CASE("RouterContact Sign and Verify", "[RC][RouterContact][signature][sign][verify]")
{
  RouterContact rc;

  SecretKey sign;
  crypto::identity_keygen(sign);

  SecretKey encr;
  crypto::encryption_keygen(encr);

  rc.enckey = encr.toPublic();
  rc.pubkey = sign.toPublic();

  REQUIRE(rc.Sign(sign));
  REQUIRE(rc.Verify(time_now_ms()));
}

TEST_CASE("RouterContact Decode Version 1", "[RC][RouterContact][V1]")
{
  RouterContact rc;

  SecretKey sign;
  crypto::identity_keygen(sign);

  SecretKey encr;
  crypto::encryption_keygen(encr);

  rc.version = 1;

  rc.enckey = encr.toPublic();
  rc.pubkey = sign.toPublic();

  REQUIRE(rc.Sign(sign));

  std::array<byte_t, 5000> encoded_buffer;
  llarp_buffer_t encoded_llarp(encoded_buffer);

  rc.BEncode(&encoded_llarp);

  encoded_llarp.sz = encoded_llarp.cur - encoded_llarp.base;
  encoded_llarp.cur = encoded_llarp.base;

  RouterContact decoded_rc;

  REQUIRE(decoded_rc.BDecode(&encoded_llarp));

  REQUIRE(decoded_rc.Verify(time_now_ms()));

  REQUIRE(decoded_rc == rc);
}

TEST_CASE("RouterContact Decode Mixed Versions", "[RC][RouterContact]")
{
  RouterContact rc1, rc2, rc3, rc4;

  rc1.version = 0;
  rc2.version = 1;
  rc3.version = 0;
  rc4.version = 1;

  SecretKey sign1, sign2, sign3, sign4;
  crypto::identity_keygen(sign1);
  crypto::identity_keygen(sign2);
  crypto::identity_keygen(sign3);
  crypto::identity_keygen(sign4);

  SecretKey encr1, encr2, encr3, encr4;
  crypto::encryption_keygen(encr1);
  crypto::encryption_keygen(encr2);
  crypto::encryption_keygen(encr3);
  crypto::encryption_keygen(encr4);

  rc1.enckey = encr1.toPublic();
  rc2.enckey = encr2.toPublic();
  rc3.enckey = encr3.toPublic();
  rc4.enckey = encr4.toPublic();
  rc1.pubkey = sign1.toPublic();
  rc2.pubkey = sign2.toPublic();
  rc3.pubkey = sign3.toPublic();
  rc4.pubkey = sign4.toPublic();

  REQUIRE(rc1.Sign(sign1));
  REQUIRE(rc2.Sign(sign2));
  REQUIRE(rc3.Sign(sign3));
  REQUIRE(rc4.Sign(sign4));

  std::vector<RouterContact> rc_vec;
  rc_vec.push_back(rc1);
  rc_vec.push_back(rc2);
  rc_vec.push_back(rc3);
  rc_vec.push_back(rc4);

  std::array<byte_t, 20000> encoded_buffer;
  llarp_buffer_t encoded_llarp(encoded_buffer);

  BEncodeWriteList(rc_vec.begin(), rc_vec.end(), &encoded_llarp);
  encoded_llarp.sz = encoded_llarp.cur - encoded_llarp.base;
  encoded_llarp.cur = encoded_llarp.base;

  std::vector<RouterContact> rc_vec_out;

  BEncodeReadList(rc_vec_out, &encoded_llarp);

  REQUIRE(rc_vec.size() == rc_vec_out.size());
  for (size_t i=0; i<4; i++)
    REQUIRE(rc_vec[i] == rc_vec_out[i]);
}

} // namespace llarp
