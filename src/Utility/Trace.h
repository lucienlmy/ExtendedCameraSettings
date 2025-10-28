#pragma once
#include <dbghelp.h>

static BOOL g_sym_initialized = FALSE;

typedef BOOL( WINAPI* pfnSymInitialize )( HANDLE, PCTSTR, BOOL );
typedef BOOL( WINAPI* pfnSymFromAddr )( HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO );
typedef BOOL( WINAPI* pfnSymGetLineFromAddr64 )( HANDLE, DWORD64, PDWORD64, PIMAGEHLP_LINE64 );
typedef BOOL( WINAPI* pfnSymSetOptions )( DWORD );

// NEW: tiny additions for per-module path + load
typedef BOOL( WINAPI* pfnSymSetSearchPathW )( HANDLE, PCWSTR );
typedef BOOL( WINAPI* pfnSymGetSearchPathW )( HANDLE, PWSTR, DWORD );
typedef DWORD64( WINAPI* pfnSymLoadModuleExW )( HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD );
typedef BOOL( WINAPI* pfnSymGetModuleInfoW64 )( HANDLE, DWORD64, PIMAGEHLP_MODULEW64 );

// NEW: small helpers (ASCII-safe)
static size_t wcslen_s_( const wchar_t* s ) { if ( !s ) return 0; const wchar_t* p = s; while ( *p ) ++p; return (size_t)( p - s ); }
static void   DirNameInplaceW( wchar_t* path ) {
    if ( !path ) return; size_t n = wcslen_s_( path );
    while ( n ) { if ( path[n - 1] == L'\\' || path[n - 1] == L'/' ) { path[n - 1] = L'\0'; return; } --n; }
    if ( path[0] ) path[0] = L'\0';
}
static void   AppendPathW( wchar_t* dst, size_t cchDst, const wchar_t* add ) {
    if ( !dst || !add ) return;
    size_t cur = wcslen_s_( dst ), addlen = wcslen_s_( add );
    if ( cur && cur < cchDst - 1 && dst[cur - 1] != L';' ) { dst[cur++] = L';'; dst[cur] = L'\0'; }
    size_t avail = ( cur < cchDst ) ? ( cchDst - cur - 1 ) : 0; if ( addlen > avail ) addlen = avail;
    for ( size_t i = 0; i < addlen; ++i ) dst[cur + i] = add[i]; dst[cur + addlen] = L'\0';
}

// NEW: best-effort ensure module owning 'addr' is known to DbgHelp and its dir is in search path
static void EnsureModuleSymbolsForAddress_( HMODULE hDbgHelp, HANDLE hProcess, DWORD64 addr ) {
    // resolve needed procs once
    static pfnSymSetSearchPathW   pSymSetSearchPathW = NULL;
    static pfnSymGetSearchPathW   pSymGetSearchPathW = NULL;
    static pfnSymLoadModuleExW    pSymLoadModuleExW = NULL;
    static pfnSymGetModuleInfoW64 pSymGetModuleInfoW64 = NULL;
    if ( !pSymSetSearchPathW )   pSymSetSearchPathW = (pfnSymSetSearchPathW)GetProcAddress( hDbgHelp, "SymSetSearchPathW" );
    if ( !pSymGetSearchPathW )   pSymGetSearchPathW = (pfnSymGetSearchPathW)GetProcAddress( hDbgHelp, "SymGetSearchPathW" );
    if ( !pSymLoadModuleExW )    pSymLoadModuleExW = (pfnSymLoadModuleExW)GetProcAddress( hDbgHelp, "SymLoadModuleExW" );
    if ( !pSymGetModuleInfoW64 ) pSymGetModuleInfoW64 = (pfnSymGetModuleInfoW64)GetProcAddress( hDbgHelp, "SymGetModuleInfoW64" );
    if ( !pSymSetSearchPathW || !pSymGetSearchPathW || !pSymLoadModuleExW || !pSymGetModuleInfoW64 ) return;

    HMODULE hMod = NULL;
    if ( !GetModuleHandleExW( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)(ULONG_PTR)addr, &hMod ) || !hMod ) {
        return;
    }

    // if already has symbols (not SymNone), nothing to do
    IMAGEHLP_MODULEW64 mi; ZeroMemory( &mi, sizeof( mi ) ); mi.SizeOfStruct = sizeof( mi );
    if ( pSymGetModuleInfoW64( hProcess, (DWORD64)hMod, &mi ) ) {
        if ( mi.SymType != SymNone ) return;
    }

    wchar_t modPath[MAX_PATH]; modPath[0] = L'\0';
    if ( !GetModuleFileNameW( hMod, modPath, MAX_PATH ) || !modPath[0] ) return;

    wchar_t dir[MAX_PATH];
    lstrcpynW( dir, modPath, MAX_PATH );
    DirNameInplaceW( dir );

    if ( dir[0] ) {
        wchar_t curPath[32768]; curPath[0] = L'\0';
        pSymGetSearchPathW( hProcess, curPath, (DWORD)( sizeof( curPath ) / sizeof( curPath[0] ) ) );
        AppendPathW( curPath, sizeof( curPath ) / sizeof( curPath[0] ), dir );
        pSymSetSearchPathW( hProcess, curPath );
    }

    // Hint DbgHelp with the on-disk path and base
    pSymLoadModuleExW( hProcess, NULL, modPath, NULL, (DWORD64)hMod, 0, NULL, 0 );
}

static BOOL GetFunctionNameFromAddress( DWORD64 dwAddress, std::string& functionName ) {

    HANDLE hProcess = GetCurrentProcess(); // CHANGED from (HANDLE)-1

    HMODULE hDbgHelp{};
    if ( ( hDbgHelp = GetModuleHandleA( "dbghelp.dll" ) ) == 0 )
        hDbgHelp = LoadLibraryA( "dbghelp.dll" );
    if ( !hDbgHelp ) return FALSE;

    pfnSymInitialize SymInitialize = (pfnSymInitialize)GetProcAddress( hDbgHelp, "SymInitialize" );
    pfnSymFromAddr   SymFromAddr = (pfnSymFromAddr)GetProcAddress( hDbgHelp, "SymFromAddr" );
    pfnSymSetOptions SymSetOptions = (pfnSymSetOptions)GetProcAddress( hDbgHelp, "SymSetOptions" );

    if ( !SymInitialize || !SymFromAddr ) {
        FreeLibrary( hDbgHelp );
        return FALSE;
    }

    if ( !g_sym_initialized ) {
        if ( SymSetOptions ) {
            // keep defaults lightweight; your system modules already work
            SymSetOptions( 0x00000004 /*SYMOPT_DEFERRED_LOADS*/ | 0x00000010 /*SYMOPT_LOAD_LINES*/ | 0x00000002 /*SYMOPT_UNDNAME*/ );
        }
        if ( !SymInitialize( hProcess, NULL, TRUE ) ) { // TRUE = invade process (preserves existing system-module behavior)
            DWORD error = GetLastError();
            if ( error != 87 ) return FALSE;
        }
        g_sym_initialized = TRUE;
    }

    // NEW: ensure owning module dir is in search path and module is symbol-loaded
    EnsureModuleSymbolsForAddress_( hDbgHelp, hProcess, dwAddress );

    DWORD64 dwDisplacement = 0;
    char buffer[sizeof( SYMBOL_INFO ) + MAX_SYM_NAME * sizeof( TCHAR )] = { 0 };
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof( SYMBOL_INFO );
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    if ( SymFromAddr( hProcess, dwAddress, &dwDisplacement, pSymbol ) ) {
        functionName = pSymbol->Name;
        return TRUE;
    }

    // Best-effort retry once (in case load raced)
    EnsureModuleSymbolsForAddress_( hDbgHelp, hProcess, dwAddress );
    if ( SymFromAddr( hProcess, dwAddress, &dwDisplacement, pSymbol ) ) {
        functionName = pSymbol->Name;
        return TRUE;
    }

    return FALSE;
}

static int StackTrace( const char* prefix, char* pTraceBuffer = nullptr, int sizeOfTraceBuffer = 0 ) {

    PVOID pFrames[UINT8_MAX] {};
    char textBuffer[MAX_STR_BLOCKREASON * 4 * 4] {};

    int len{};
    size_t bufSize = ARRAYSIZE( textBuffer );

    auto count = RtlCaptureStackBackTrace( 2, ARRAYSIZE( pFrames ), pFrames, NULL );//LI_FN( RtlCaptureStackBackTrace ).get()( 0, ARRAYSIZE( pFrames ), pFrames, NULL );

    auto hMainModule = GetModuleHandleA(NULL);

    const HMODULE hOurModule = GetActiveModule(); // our DLL module handle

    PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)( (UINT64)hOurModule + ( (PIMAGE_DOS_HEADER)hOurModule )->e_lfanew );
    DWORD ourModuleSize = pNtH->OptionalHeader.SizeOfImage;

    for ( int ndx = 0; ndx < count; ndx++ ) {

        HMODULE hThisModuleBase = GetModuleBase( ( PBYTE )pFrames[ndx], false ); //true

        bool bIsMainModule = hMainModule == hThisModuleBase;

        auto bIsOurModule = ( DWORD64 )pFrames[ndx] >= ( DWORD64 )hOurModule &&
                            ( DWORD64 )pFrames[ndx] < ( DWORD64 )hOurModule + ourModuleSize;

        HMODULE hModule = bIsOurModule ? hOurModule : hThisModuleBase;

        CHAR fileName[MAX_PATH] = "<NULL>";

        GetModuleFileNameA( hThisModuleBase, fileName, ARRAYSIZE( fileName ) );

        const auto shortFilename = GetFilenameWithoutPath( fileName, false );

        auto idaAddr = ( ( DWORD64 )pFrames[ndx] - ( DWORD64 )hModule ) + ( bIsMainModule ? 0x140000000 : 0x180000000 );

        std::string symbolName;

#ifdef RLB_DEBUG

        auto bShowFullSymbolName = bIsMainModule ? false : GetFunctionNameFromAddress( ( DWORD64 )pFrames[ndx], symbolName );
#else
        auto bShowFullSymbolName = false;
#endif

        len += snprintf( &textBuffer[len], bufSize - len, "Trace %3d %s %016llx (%s+%llX)\n",
                         ndx, bShowFullSymbolName ? ( GetFilenameWithoutPath( fileName, true ) + "::" + symbolName ).c_str() : "", idaAddr,
                         shortFilename.c_str(), ( DWORD64 )pFrames[ndx] - ( DWORD64 )hModule );
    }

    strncpy_s( pTraceBuffer, sizeOfTraceBuffer, textBuffer, len + 1 );

    return count;
}
