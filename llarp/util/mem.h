#pragma once

#include <cstdint>
#include <cstdlib>

/** constant time memcmp */
bool llarp_eq(const void* a, const void* b, size_t sz);
