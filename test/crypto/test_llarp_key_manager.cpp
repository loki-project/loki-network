#include "test_util.hpp"

#include <llarp/config/key_manager.hpp>

#include <llarp/crypto/crypto.hpp>
#include <llarp/crypto/crypto_libsodium.hpp>

#include <functional>
#include <random>

#include <string>
#include <catch2/catch.hpp>

using namespace ::llarp;

struct KeyManagerTest
{
  // paranoid file guards for anything KeyManager might touch
  test::FileGuard m_rcFileGuard;
  test::FileGuard m_encFileGuard;
  test::FileGuard m_transportFileGuard;
  test::FileGuard m_identFileGuard;

  KeyManagerTest()
      : m_rcFileGuard(our_rc_filename)
      , m_encFileGuard(our_enc_key_filename)
      , m_transportFileGuard(our_transport_key_filename)
      , m_identFileGuard(our_identity_filename)
  {}

  /// generate a valid "rc.signed" file
  bool
  generateRcFile()
  {
    RouterContact rc;
    return rc.Write(our_rc_filename);
  }
};

TEST_CASE_METHOD(KeyManagerTest, "Backup file by moving moves existing files")
{
  fs::path p = test::randFilename();
  REQUIRE_FALSE(fs::exists(p));

  // touch file
  std::fstream f;
  f.open(p.string(), std::ios::out);
  f.close();

  KeyManager::backupFileByMoving(p.string());

  REQUIRE_FALSE(fs::exists(p));

  fs::path moved = p.string() + ".0.bak";

  REQUIRE(fs::exists(moved));

  test::FileGuard guard(moved);
};

TEST_CASE_METHOD(KeyManagerTest, "Backup file by moving doesnt touch non existent files")
{
  fs::path p = test::randFilename();
  REQUIRE_FALSE(fs::exists(p));

  KeyManager::backupFileByMoving(p.string());

  REQUIRE_FALSE(fs::exists(p));

  fs::path moved = p.string() + ".0.bak";

  REQUIRE_FALSE(fs::exists(moved));
}

TEST_CASE_METHOD(KeyManagerTest, "Backup file by moving fails if backup names are exausted")
{
  fs::path base = test::randFilename();
  REQUIRE_FALSE(fs::exists(base));

  // touch file
  {
    std::fstream f;
    f.open(base.string(), std::ios::out);
    f.close();
  }

  test::FileGuard guard(base);

  constexpr uint32_t numBackupNames = 9;
  std::vector<test::FileGuard> guards;
  guards.reserve(numBackupNames);

  // generate backup files foo.0.bak through foo.9.bak
  for (uint32_t i = 0; i < numBackupNames; ++i)
  {
    fs::path p = base.string() + "." + std::to_string(i) + ".bak";

    std::fstream f;
    f.open(p.string(), std::ios::out);
    f.close();

    guards.emplace_back(p);

    REQUIRE(fs::exists(p));
  }

  REQUIRE_FALSE(KeyManager::backupFileByMoving(base.string()));
};

TEST_CASE_METHOD(KeyManagerTest, "Initialize makes keyfiles")
{
  llarp::Config conf{fs::current_path()};
  conf.Load();

  KeyManager keyManager;
  REQUIRE(keyManager.initialize(conf, true, true));

  // KeyManager doesn't generate RC file, but should generate others
  REQUIRE_FALSE(fs::exists(our_rc_filename));

  REQUIRE(fs::exists(our_enc_key_filename));
  REQUIRE(fs::exists(our_transport_key_filename));
  REQUIRE(fs::exists(our_identity_filename));
}

TEST_CASE_METHOD(KeyManagerTest, "Initialize respects gen flag")
{
  llarp::Config conf{fs::current_path()};
  conf.Load();

  KeyManager keyManager;
  REQUIRE_FALSE(keyManager.initialize(conf, false, true));

  // KeyManager shouldn't have touched any files without (genIfAbsent == true)
  REQUIRE_FALSE(fs::exists(our_rc_filename));
  REQUIRE_FALSE(fs::exists(our_enc_key_filename));
  REQUIRE_FALSE(fs::exists(our_transport_key_filename));
  REQUIRE_FALSE(fs::exists(our_identity_filename));
}

TEST_CASE_METHOD(KeyManagerTest, "Initialize detects bad rc file")
{
  llarp::Config conf{fs::current_path()};
  conf.Load();

  conf.lokid.whitelistRouters = false;

  std::fstream f;
  f.open(our_rc_filename, std::ios::out);
  f << "bad_rc_file";
  f.close();

  KeyManager keyManager;
  REQUIRE(keyManager.initialize(conf, true, true));
  REQUIRE(keyManager.needBackup());

  REQUIRE(fs::exists(our_enc_key_filename));
  REQUIRE(fs::exists(our_transport_key_filename));
  REQUIRE(fs::exists(our_identity_filename));

  // test that keys are sane
  SecretKey key;

  key.Zero();
  REQUIRE(key.LoadFromFile(our_enc_key_filename));
  REQUIRE_FALSE(key.IsZero());

  key.Zero();
  REQUIRE(key.LoadFromFile(our_transport_key_filename));
  REQUIRE_FALSE(key.IsZero());

  key.Zero();
  REQUIRE(key.LoadFromFile(our_identity_filename));
  REQUIRE_FALSE(key.IsZero());
}
