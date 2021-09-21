#pragma once
#include "lokinet_export.h"
#ifdef __cplusplus
extern "C"
{
#endif

  /// change our network id globally across all contexts
  void EXPORT
  lokinet_set_netid(const char*);

  /// get our current netid
  /// must be free()'d after use
  const char* EXPORT
  lokinet_get_netid();

  /// set log level
  /// possible values: trace, debug, info, warn, error, none
  /// return 0 on success
  /// return non zero on fail
  int EXPORT
  lokinet_log_level(const char*);

  /// @brief take in hex and turn it into base32z
  /// @return value must be free()'d later
  char* EXPORT
  lokinet_hex_to_base32z(const char* hex);

#ifdef __cplusplus
}
#endif
