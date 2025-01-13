#include <llarp/path/path.hpp>
#include <catch2/catch.hpp>

using Path_t   = llarp::path::Path;
using Path_ptr = llarp::path::Path_ptr;
using Set_t    = llarp::path::Path::UniqueEndpointSet_t;
using RC_t     = llarp::RelayContact;

static RC_t
MakeHop(const char name)
{
  RC_t rc;
  rc.pubkey.Fill(name);
  return rc;
}

static Path_ptr
MakePath(std::vector< char > hops)
{
  std::vector< RC_t > pathHops;
  for(const auto& hop : hops)
    pathHops.push_back(MakeHop(hop));
  return std::make_shared< Path_t >(pathHops, std::weak_ptr<llarp::path::PathSet>{}, 0, "test");
}

TEST_CASE("UniqueEndpointSet_t has unique endpoints", "[path]")
{
  Set_t set;
  REQUIRE(set.empty());
  const auto inserted_first =
      set.emplace(MakePath({'a', 'b', 'c', 'd'})).second;
  REQUIRE(inserted_first);
  const auto inserted_again =
      set.emplace(MakePath({'a', 'b', 'c', 'd'})).second;
  REQUIRE(not inserted_again);
  const auto inserted_second =
      set.emplace(MakePath({'d', 'c', 'b', 'a'})).second;
  REQUIRE(inserted_second);
}
