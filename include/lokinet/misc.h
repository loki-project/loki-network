#pragma once
#include "export.h"
#ifdef __cplusplus
extern "C"
{
#endif

    /// change our network id globally across all contexts
    void EXPORT lokinet_set_netid(const char* netid);

    /// get our current netid
    /// must be free()'d after use
    const char* EXPORT lokinet_get_netid();

    /// set log level
    /// possible values: trace, debug, info, warn, error, critical, none
    /// return 0 on success
    /// return non zero on fail
    int EXPORT lokinet_log_level(const char* level);

    /// Function pointer to invoke with lokinet log messages
    typedef void (*lokinet_logger_func)(const char* message, void* context);

    /// Optional function to call when flushing lokinet log messages; can be NULL if flushing is not
    /// meaningful for the logging system.
    typedef void (*lokinet_logger_sync)(void* context);

    /// set a custom logger function; it is safe (and often desirable) to call this before calling
    /// initializing lokinet via lokinet_context_new.
    void EXPORT lokinet_set_syncing_logger(lokinet_logger_func func, lokinet_logger_sync sync, void* context);

    /// shortcut for calling `lokinet_set_syncing_logger` with a NULL sync
    void EXPORT lokinet_set_logger(lokinet_logger_func func, void* context);

    /// @brief take in hex and turn it into base32z
    /// @return value must be free()'d later
    char* EXPORT lokinet_hex_to_base32z(const char* hex);

#ifdef __cplusplus
}
#endif
