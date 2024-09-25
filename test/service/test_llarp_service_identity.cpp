#include <llarp/crypto/crypto.hpp>
#include <llarp/crypto/crypto_libsodium.hpp>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <llarp/path/path.hpp>
#include <llarp/service/address.hpp>
#include <llarp/service/identity.hpp>
#include <llarp/service/intro_set.hpp>
#include <llarp/util/time.hpp>

#include <catch2/catch.hpp>

using namespace llarp;

TEST_CASE("test service address from string")
{
  
  service::Identity ident{};
  
  auto str = ident.pub.Addr().ToString();
  service::Address addr;
  CHECK(addr.FromString(str));
  CHECK(addr == ident.pub.Addr());
}

TEST_CASE("test service::Identity throws on error")
{
  fs::path p = test::randFilename();
  CHECK(not fs::exists(fs::status(p)));

  test::FileGuard guard(p);
  std::error_code code;

  std::fstream file;
  file.open(p.string(), std::ios::out);
  CHECK(file.is_open());
  file << p;
  file.close();

  service::Identity identity;
  REQUIRE_THROWS(identity.EnsureKeys(p, false));
}


TEST_CASE("test subkey derivation", "[crypto]")
{
  // These values came out of a run of Tor's test code, so that we can confirm we are doing the same
  // blinding subkey crypto math as Tor.  Our hash value is generated differently so we use the hash
  // from a Tor random test suite run.

  AlignedBuffer<32> seed{{
    0xd0, 0x98, 0x9d, 0x83, 0x0e, 0x03, 0xe1, 0x4e, 0xf6, 0xaf, 0x71, 0xa0, 0xa1, 0xfc, 0x88, 0x38, 0xac, 0xfc, 0xd8, 0x95, 0x06, 0x54, 0x9f, 0x3e, 0xdb, 0xb0, 0xf5, 0x3a, 0xc9, 0x0e, 0x47, 0x90,
  }};
  AlignedBuffer<64> root_key_data{{
    0xc0, 0xe6, 0x58, 0xd6, 0x01, 0xc1, 0xb4, 0xc2, 0x94, 0xb8, 0xf7, 0xa3, 0xec, 0x3e, 0x81, 0xd6, 0x82, 0xb4, 0x89, 0x5c, 0x6d, 0xbf, 0x5c, 0x6e, 0x20, 0xad, 0x39, 0x8f, 0xf4, 0x8f, 0x43, 0x4f,
    0x56, 0x4f, 0xdc, 0x22, 0x33, 0x19, 0xb9, 0xbb, 0x4e, 0xc0, 0xba, 0x84, 0x2d, 0xe3, 0xde, 0xf2, 0x26, 0xe8, 0xf7, 0xa8, 0x8f, 0x82, 0x41, 0xe3, 0x1f, 0x5d, 0xe5, 0x56, 0x3a, 0xf4, 0x5e, 0x3c,
  }};

  AlignedBuffer<32> root_pub_data{{
    0x4a, 0x34, 0x3f, 0x9e, 0xf3, 0xda, 0x3d, 0x80, 0x07, 0xc7, 0x09, 0xf9, 0x2f, 0x72, 0xd3, 0x76, 0x56, 0x5a, 0x4c, 0x13, 0xdf, 0xb8, 0xce, 0xc8, 0x53, 0x77, 0x0a, 0x99, 0xbc, 0x06, 0xa7, 0xc0,
  }};
  AlignedBuffer<32> hash{{
    0x64, 0xad, 0xde, 0x17, 0x69, 0x33, 0x92, 0x25, 0x9c, 0xa3, 0xd7, 0x85, 0xa5, 0x2d, 0x3a, 0xa5, 0xa3, 0x9c, 0xdb, 0x99, 0x57, 0xac, 0x54, 0x14, 0x4f, 0x11, 0xa9, 0x90, 0xa0, 0xca, 0xcb, 0xfe,
  }};
  AlignedBuffer<64> derived_key_data{{
    0x96, 0x02, 0xba, 0x16, 0x87, 0x40, 0xb7, 0xb6, 0xc9, 0x0f, 0x85, 0x7b, 0xdc, 0xa9, 0x13, 0x9d, 0x1b, 0xf5, 0x01, 0x54, 0xd1, 0xd1, 0x8f, 0x75, 0x06, 0x4d, 0x4c, 0xea, 0x33, 0xc4, 0xc6, 0x00,
    0xb0, 0xef, 0x29, 0x37, 0x7c, 0xe9, 0x84, 0x43, 0x5a, 0x79, 0xa2, 0x3b, 0xef, 0xcd, 0x1c, 0x43, 0xf1, 0x88, 0xff, 0x50, 0xaf, 0x9c, 0x07, 0x6a, 0xc6, 0x19, 0xfb, 0xcc, 0x5d, 0x48, 0x75, 0x92,
  }};
  AlignedBuffer<32> derived_pub_data{{
    0x13, 0xa6, 0x61, 0x5b, 0x78, 0x64, 0x03, 0xd4, 0x8a, 0x88, 0xaa, 0x0d, 0x89, 0xdf, 0x08, 0x46, 0xb3, 0x2f, 0xa9, 0xbb, 0xa8, 0xcc, 0xe1, 0xac, 0x4c, 0xae, 0xc9, 0xd2, 0xf1, 0x35, 0xd1, 0x33,
  }};

  SecretKey root{seed};
  CHECK(root.toPublic().as_array() == root_pub_data.as_array());

  PrivateKey root_key;
  CHECK(root.toPrivate(root_key));
  CHECK(root_key.as_array() == root_key_data.as_array());

  PrivateKey aprime; // a'
  CHECK(crypto::derive_subkey_private(aprime, root, 0, &hash));

  // We use a different signing hash than Tor
  // only the private key value (the first 32 bytes) will match:
  CHECK(std::memcmp(aprime.data(), derived_key_data.data(), 32) == 0);

  PubKey Aprime; // A'
  CHECK(crypto::derive_subkey(Aprime, root.toPublic(), 0, &hash));
  CHECK(Aprime.as_array() == derived_pub_data.as_array());
}

TEST_CASE("test root key signing" , "[crypto]")
{
  SecretKey root_key;
  crypto::identity_keygen(root_key);

  // We have our own reimplementation of sodium's signing function which can work with derived
  // private keys (unlike sodium's built-in which requires starting from a seed).  This tests that
  // signing using either path produces an identical signature.

  const std::string nibbs = "Nibbler";
  llarp_buffer_t nibbs_buf{nibbs.data(), nibbs.size()};

  Signature sig_sodium;
  CHECK(crypto::sign(sig_sodium, root_key, nibbs_buf));

  PrivateKey root_privkey;
  CHECK(root_key.toPrivate(root_privkey));
  Signature sig_ours;
  CHECK(crypto::sign(sig_ours, root_privkey, nibbs_buf));

  CHECK(sig_sodium == sig_ours);
}

TEST_CASE("Test generate derived key", "[crypto]")
{
  SecretKey root_key;
  crypto::identity_keygen(root_key);

  PrivateKey root_privkey;
  CHECK(root_key.toPrivate(root_privkey));

  PrivateKey a;
  PubKey A;
  CHECK(root_key.toPrivate(a));
  CHECK(a.toPublic(A));
  CHECK(A == root_key.toPublic());

  {
    // paranoid check to ensure this works as expected
    PubKey aB;
    crypto_scalarmult_ed25519_base(aB.data(), a.data());
    CHECK(A == aB);
  }

  PrivateKey aprime; // a'
  CHECK(crypto::derive_subkey_private(aprime, root_key, 1));

  PubKey Aprime; // A'
  CHECK(crypto::derive_subkey(Aprime, A, 1));

  // We should also be able to derive A' via a':
  PubKey Aprime_alt;
  CHECK(aprime.toPublic(Aprime_alt));

  CHECK(Aprime == Aprime_alt);

  // Generate using the same constant and make sure we get an identical privkey (including the
  // signing hash value)
  PrivateKey aprime_repeat;
  CHECK(crypto::derive_subkey_private(aprime_repeat, root_key, 1));
  CHECK(aprime_repeat == aprime);

  // Generate another using a different constant and make sure we get something different
  PrivateKey a2;
  PubKey A2;
  CHECK(crypto::derive_subkey_private(a2, root_key, 2));
  CHECK(crypto::derive_subkey(A2, A, 2));
  CHECK(A2 != Aprime);
  CHECK(a2.ToHex().substr(0, 64) != aprime.ToHex().substr(0, 64));
  CHECK(a2.ToHex().substr(64) != aprime.ToHex().substr(64)); // The hash should be different too
}

TEST_CASE("Test signing with derived key", "[crypto]")
{
  SecretKey root_key;
  crypto::identity_keygen(root_key);

  PrivateKey root_privkey;
  root_key.toPrivate(root_privkey);

  PrivateKey a;
  PubKey A;
  root_key.toPrivate(a);
  a.toPublic(A);

  PrivateKey aprime; // a'
  crypto::derive_subkey_private(aprime, root_key, 1);

  PubKey Aprime; // A'
  crypto::derive_subkey(Aprime, A, 1);

  const std::string s = "Jeff loves one-letter variable names.";
  llarp_buffer_t buf(s.data(), s.size());

  Signature sig;
  
  CHECK(crypto::sign(sig, aprime, buf));
  CHECK(crypto::verify(Aprime, buf, sig));
}

TEST_CASE("Test sign and encrypt introset", "[crypto]")
{
  service::Identity ident;
  ident.RegenerateKeys();
  service::Address addr;
  CHECK(ident.pub.CalculateAddress(addr.as_array()));
  service::IntroSet introset;
  auto now = time_now_ms();
  introset.timestampSignedAt = now;
  while(introset.intros.size() < 10)
  {
    service::Introduction intro;
    intro.expiresAt = now + (path::default_lifetime / 2);
    intro.router.Randomize();
    intro.pathID.Randomize();
    introset.intros.emplace_back(std::move(intro));
  }

  const auto maybe = ident.EncryptAndSignIntroSet(introset, now);
  CHECK(maybe.has_value());
  CHECK(maybe->Verify(now));
  PubKey blind_key;
  const PubKey root_key(addr.as_array());
  CHECK(crypto::derive_subkey(blind_key, root_key, 1));
  CHECK(blind_key == maybe->derivedSigningKey);
}
