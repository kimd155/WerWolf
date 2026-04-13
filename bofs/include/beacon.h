/**
 * beacon.h  - Minimal Beacon-compatible API header for BOF development
 * ===================================================================
 *
 * BOFs (Beacon Object Files) are position-independent COFF objects that
 * run inside a loader's process.  They can't use the standard C runtime
 * directly  - every external function must be declared as a DLL import
 * using the MODULE$FUNCTION naming convention.
 *
 * The loader resolves these at load time:
 *   __imp_MODULE$FUNCTION  ->  LoadLibrary("MODULE") + GetProcAddress("FUNCTION")
 *   __imp_BeaconOutput     ->  loader's internal callback
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

/* ── Beacon Output Types ── */
#define CALLBACK_OUTPUT 0
#define CALLBACK_ERROR  1

/* ── Core Beacon API (provided by the loader) ── */
DECLSPEC_IMPORT void BeaconOutput(int type, char *data, int len);

/* ── C Runtime via MSVCRT (always loaded on Windows) ── */
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snprintf(char *buf, size_t count, const char *fmt, ...);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *dest, int ch, size_t count);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *str);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_stricmp(const char *s1, const char *s2);

/* ── Convenience macros (use AFTER all #includes) ── */
#define _snprintf MSVCRT$_snprintf
#define memset    MSVCRT$memset
#define strlen    MSVCRT$strlen
#define _stricmp  MSVCRT$_stricmp

#ifdef __cplusplus
}
#endif
