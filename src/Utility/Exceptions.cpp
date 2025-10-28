#include "stdafx.h"

#include "Trace.h"

CRITICAL_SECTION g_execeptionHandlerCritSect = { 0 };
bool g_hasInitialized = false;

void InitExceptionHandling() {

	if ( !g_hasInitialized ) {

		InitializeCriticalSection( &g_execeptionHandlerCritSect );

		auto filePath = GetWorkingDirectory() + "exception.log";
		DeleteFileA( filePath.c_str() );
		AddVectoredExceptionHandler( TRUE, ExceptionHandler );

		g_hasInitialized = true;
	}
}

void ShutdownExceptionHandling() {

	if ( !g_hasInitialized )
		return;

	LOG( "Shutting down exception handlers..." )

	RemoveVectoredExceptionHandler( ExceptionHandler );

	DeleteCriticalSection( &g_execeptionHandlerCritSect );

	g_hasInitialized = false;


LONG CALLBACK ExceptionHandler( PEXCEPTION_POINTERS exceptionInfo ) {

	PEXCEPTION_RECORD record = exceptionInfo->ExceptionRecord; PCONTEXT context = exceptionInfo->ContextRecord;

	if ( record->ExceptionAddress == 0 || record->ExceptionCode < 0x80000000 ||
		record->ExceptionCode == SVL_MSVC_EXCEPTION ) { // these exceptions (less than 0x80000000) are non critical, let someone else handle it...

		return EXCEPTION_CONTINUE_SEARCH;
	}

	if ( record->ExceptionCode == STATUS_ASSERTION_FAILURE ||
		record->ExceptionCode == EXCEPTION_BREAKPOINT ) {

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	EnterCriticalSection( &g_execeptionHandlerCritSect );

	HMODULE hModule; size_t moduleSize = 0;

	const HMODULE hOurModule = GetActiveModule(); // our DLL module handle

	PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)( (UINT64)hOurModule + ( (PIMAGE_DOS_HEADER)hOurModule )->e_lfanew );
	auto ourModuleSize = pNtH->OptionalHeader.SizeOfImage;

	auto bIsOurModule = (DWORD64)record->ExceptionAddress >= (DWORD64)hOurModule && (DWORD64)record->ExceptionAddress < (DWORD64)hOurModule + ourModuleSize;

	if ( bIsOurModule ) {
		hModule = hOurModule;
		moduleSize = ourModuleSize;
	}

	else
		hModule = GetModuleBase( (PBYTE)record->ExceptionAddress, moduleSize, true );

	if ( hModule == nullptr ) {

		LOG( "The module that threw the exception may be hidden or have tampered PE headers" )
			//Handle exception not associated with any module.
	}

	CHAR fileName[MAX_PATH] = "<NULL>";
	std::vector<char> traceBuffer( 1024 * 4 );

	if ( GetModuleFileNameA( hModule, fileName, sizeof( fileName ) ) == 0 ) {
		//Handle error.
	}	

	int nFrames = StackTrace( "trace", traceBuffer.data(), traceBuffer.size() );

	auto filePath = GetWorkingDirectory() + "exception.log";

#ifdef RLB_DEBUG
	std::ofstream logFile( filePath, std::ios::app );
#else
	std::ofstream logFile( filePath );
#endif

	if ( logFile.is_open() ) {

		//PrintModules( file );

		logFile << FormatString( "[%s] %s (0x%lX) @ Address 0x%llX (%s+0x%llX base:0x%llX) Platform: %s Our Base: %p\nRIP: %llX RSP: %llX RBP: %llX RAX: %llX\nRBX: %llX RCX: %llX RDX: %llX RDI: %llX RSI: %llX\nR8: %llX R9: %llX R10: %llX R11: %llX\nR12: %llX R13: %llX R14: %llX R15: %llX\nfirst 10 bytes: %s\n\n%s\n\n",
			GetShortTimeString().c_str(),
			GetFriendlyErrorMessage( record ).c_str(),
			record->ExceptionCode,
			record->ExceptionAddress,
			GetFilenameWithoutPath( fileName, false ).c_str(),
			( (UINT64)record->ExceptionAddress - (UINT64)hModule ),
			(PVOID)hModule,
			isEnhancedVersion() ? "gtav-enhanced" : "gtav-legacy",
			(PVOID)GetActiveModule(),
			context->Rip,
			context->Rsp,
			context->Rbp,
			context->Rax,
			context->Rbx,
			context->Rcx,
			context->Rdx,
			context->Rdi,
			context->Rsi,
			context->R8,
			context->R9,
			context->R10,
			context->R11,
			context->R12,
			context->R13,
			context->R14,
			context->R15,
			!IsBadReadPtr( record->ExceptionAddress, 8 ) ? HexString( (PBYTE)record->ExceptionAddress, 10, true ).c_str() : "<invalid>",
			nFrames ? traceBuffer.data() : ""
		);

		logFile.close();
	}

	LeaveCriticalSection( &g_execeptionHandlerCritSect );

	return EXCEPTION_CONTINUE_SEARCH;
}

