#pragma once
#include <dbghelp.h>

#define SVL_THREAD_NAMING_EXCEPTION 0x406D1388
#define SVL_MSVC_EXCEPTION 0xE06D7363
#define SVL_COM_CALLABLE_RT_EXCEPTION 0xE0434352
#define SVL_CLR_DBG_DATA_CHECKSUM_EXCEPTION 0x31415927

extern CRITICAL_SECTION g_execeptionHandlerCritSect;
extern bool g_hasInitialized;

void InitExceptionHandling();

void ShutdownExceptionHandling();

LONG CALLBACK ExceptionHandler( PEXCEPTION_POINTERS exceptionInfo );
