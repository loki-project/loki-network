#pragma once

#if (!(defined(__clang__)) && defined(__GNUC__) && __GNUC__ < 10)
#define CONCEPT_COMPAT bool
#else
#define CONCEPT_COMPAT
#endif
