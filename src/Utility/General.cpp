#include "stdafx.h"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <tchar.h>

static HMODULE ourModule;

HMODULE Utility::GetActiveModule() {
    HMODULE hModule = NULL;

    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                      reinterpret_cast<LPCSTR>(&GetActiveModule),
                      &hModule);

    return hModule;
}

std::string Utility::GetModuleName(HMODULE hModule) {
    TCHAR inBuf[MAX_PATH];

    if (!hModule)
        hModule = GetActiveModule();

    GetModuleFileName(hModule, inBuf, MAX_PATH);

    auto str = std::string(inBuf);

    auto seperator = str.find_last_of("\\");

    if (seperator != std::string::npos)
        seperator += 1;

    return str.substr(seperator, str.find_last_of(".") - seperator);
}

std::string Utility::GetWorkingDirectory() {
    HMODULE hModule = GetActiveModule();

    TCHAR inBuf[MAX_PATH];

    GetModuleFileName(hModule, inBuf, MAX_PATH);

    auto str = std::string(inBuf);

    auto seperator = str.find_last_of("\\");

    if (seperator != std::string::npos)
        seperator += 1;

    return str.substr(0, seperator);

}

std::string Utility::GetShortTimeString() {
    time_t t = time(NULL);

    struct tm timeinfo;

    localtime_s(&timeinfo, &t);

    return FormatString("%02d:%02d:%02d",
                        timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

bool Utility::FileExists(std::string fileName) {
    std::ifstream infile(fileName);
    return infile.good();
}

std::string Utility::GetFilenameWithoutPath( const std::string& string, const bool removeExtension ) {

    auto pos = string.find_last_of( "/\\" );

    if ( pos == std::string::npos ) return string;

    pos += 1;

    return string.substr( pos, ( removeExtension ?
        string.find_first_of( '.' ) : string.length() ) - pos );
}

void Utility::SplitString(std::string str, std::string splitBy, std::vector<std::string>& tokens) {
    tokens.push_back(str);

    auto splitLen = splitBy.size();

    while (true) {
        auto frag = tokens.back();

        auto splitAt = frag.find(splitBy);

        if (splitAt == std::string::npos) {
            break;
        }

        tokens.back() = frag.substr(0, splitAt);

        tokens.push_back(frag.substr(splitAt + splitLen, frag.size() - (splitAt + splitLen)));
    }
}

void Utility::ReplaceAll( std::string& str, const std::string& from, const std::string& to ) {
    size_t start_pos = 0;
    while ( ( start_pos = str.find( from, start_pos ) ) != std::string::npos ) {
        str.replace( start_pos, from.length(), to );
        start_pos += to.length();
    }
}

void Utility::ToLower(std::string& str) {
    transform(str.begin(), str.end(), str.begin(), std::tolower);
}

unsigned Utility::GetHashKey(std::string str) {
    unsigned int hash = 0;
    for (int i = 0; i < str.size(); ++i) {
        hash += str[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

unsigned int Utility::StringToHash(std::string str) {

    char * p;
    unsigned long numericHash = strtoul(str.c_str(), &p, 10);

    return *p != '\0' ? GetHashKey(str) : 
        static_cast<unsigned int>(numericHash);
}

std::string Utility::HexString( BYTE* data, int len, bool idaStyle ) {
    std::stringstream ss;

    if ( data != 0 && len > 0 ) {
        for ( int i = 0; i < len; ++i ) {
            ss << ( idaStyle ? ( i == 0 ? "" : " " ) : "\\x" ) <<
                std::uppercase <<
                std::setfill( '0' ) <<
                std::setw( 2 ) <<
                std::hex << static_cast<int>( data[i] );
        }
    }
    return ss.str();
}

bool Utility::IsCanonicalAddress( uintptr_t Address ) {
#ifndef _WIN64
    return true;
#else
    return ( ( ( Address & 0xFFFF800000000000 ) + 0x800000000000 ) & ~0x800000000000 ) == 0;
#endif //_WIN64
}

bool Utility::IsMemoryReadable( LPCVOID lpcPtr ) {

    MEMORY_BASIC_INFORMATION mbi = { 0 };

    if ( !IsCanonicalAddress( reinterpret_cast<uintptr_t>( lpcPtr ) ) )
        return false;

    if ( sizeof( mbi ) != VirtualQuery( lpcPtr, &mbi, sizeof( mbi ) ) ||
        mbi.State != MEM_RESERVE || ( mbi.Protect & ( PAGE_NOACCESS | PAGE_GUARD ) ) != 0 )
        return false;

    return ( mbi.Protect & ( PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) ) != 0;
}

HMODULE Utility::GetModuleBase( PBYTE address, bool checkMappedModule ) {
    size_t _discard = { 0 };

    return GetModuleBase( address, _discard, checkMappedModule );
}

HMODULE Utility::GetModuleBase( PBYTE address, size_t& moduleSize, bool checkMappedModule ) {
    HMODULE foundModule = 0;

    moduleSize = 0;

    if ( !GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>( address ),
        &foundModule ) && checkMappedModule ) {

        if ( address && IsMemoryReadable( address ) && *(WORD*)address == IMAGE_DOS_SIGNATURE ) {
            foundModule = reinterpret_cast<HMODULE>( address );
        }

        else {
            MEMORY_BASIC_INFORMATION mbi = { 0 };

            PVOID moduleFromAddress = address;

            while ( VirtualQuery( moduleFromAddress, &mbi, sizeof( mbi ) ) == sizeof( mbi ) && mbi.Protect & PAGE_EXECUTE_READ ) {
                moduleFromAddress = ( (PBYTE)mbi.BaseAddress - 1 );
            }

            if ( IsMemoryReadable( moduleFromAddress ) ) {

                moduleFromAddress = mbi.BaseAddress;

                if ( *(WORD*)moduleFromAddress == IMAGE_DOS_SIGNATURE ) {

                    foundModule = reinterpret_cast<HMODULE>( moduleFromAddress );
                }
            }
        }
    }

    if ( foundModule != 0 ) {

        const auto header = reinterpret_cast<PIMAGE_DOS_HEADER>( foundModule );
        const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>( reinterpret_cast<uintptr_t>( foundModule ) + header->e_lfanew );
        moduleSize = ntHeader->OptionalHeader.SizeOfImage;
    }

    return foundModule;
}

PVOID Utility::GetSectionBase(HMODULE moduleBase, const std::string& sectionName, size_t& sectionSize)
{
	const auto header = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);

	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(moduleBase) + header->e_lfanew);

	const auto imageSectionHeader = (PIMAGE_SECTION_HEADER)(ntHeader + 1);

	for (auto i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) { // DLL MUST NOT EXCEED 0x100000 IN SIZE

		if (!memcmp(imageSectionHeader[i].Name, sectionName.c_str(), sectionName.size()))
		{
			sectionSize = imageSectionHeader[i].Misc.VirtualSize;

			return (PVOID)((uintptr_t)moduleBase + imageSectionHeader[i].VirtualAddress);
		}
	}

	return NULL;
}

std::string Utility::GetFriendlyErrorMessage( EXCEPTION_RECORD* record ) {

    LPSTR lpszTemp = NULL;
    typedef ULONG( NTAPI* RtlNtStatusToDosError_t )( NTSTATUS );

    switch ( record->ExceptionCode ) {
    case EXCEPTION_ACCESS_VIOLATION:
        return std::string("EXCEPTION_ACCESS_VIOLATION");
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        return std::string("EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
    case EXCEPTION_BREAKPOINT:
        return std::string("EXCEPTION_BREAKPOINT");
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        return std::string("EXCEPTION_DATATYPE_MISALIGNMENT");
    case EXCEPTION_FLT_DENORMAL_OPERAND:
        return std::string("EXCEPTION_FLT_DENORMAL_OPERAND");
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        return std::string("EXCEPTION_FLT_DIVIDE_BY_ZERO");
    case EXCEPTION_FLT_INEXACT_RESULT:
        return std::string("EXCEPTION_FLT_INEXACT_RESULT");
    case EXCEPTION_FLT_INVALID_OPERATION:
        return std::string("EXCEPTION_FLT_INVALID_OPERATION");
    case EXCEPTION_FLT_OVERFLOW:
        return std::string("EXCEPTION_FLT_OVERFLOW");
    case EXCEPTION_FLT_STACK_CHECK:
        return std::string("EXCEPTION_FLT_STACK_CHECK");
    case EXCEPTION_FLT_UNDERFLOW:
        return std::string("EXCEPTION_FLT_UNDERFLOW");
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        return std::string("EXCEPTION_ILLEGAL_INSTRUCTION");
    case EXCEPTION_IN_PAGE_ERROR:
        return std::string("EXCEPTION_IN_PAGE_ERROR");
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        return std::string("EXCEPTION_INT_DIVIDE_BY_ZERO");
    case EXCEPTION_INT_OVERFLOW:
        return std::string("EXCEPTION_INT_OVERFLOW");
    case EXCEPTION_INVALID_DISPOSITION:
        return std::string("EXCEPTION_INVALID_DISPOSITION");
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        return std::string("EXCEPTION_NONCONTINUABLE_EXCEPTION");
    case EXCEPTION_PRIV_INSTRUCTION:
        return std::string("EXCEPTION_PRIV_INSTRUCTION");
    case EXCEPTION_SINGLE_STEP:
        return std::string("EXCEPTION_SINGLE_STEP");
    case EXCEPTION_STACK_OVERFLOW:
        return std::string("EXCEPTION_STACK_OVERFLOW");
    case SVL_MSVC_EXCEPTION:
        return std::string("SVL_MSVC_EXCEPTION");
    case SVL_COM_CALLABLE_RT_EXCEPTION:
        return std::string("SVL_COM_CALLABLE_RT_EXCEPTION");
    case SVL_THREAD_NAMING_EXCEPTION:
        return std::string("SVL_THREAD_NAMING_EXCEPTION");
    case SVL_CLR_DBG_DATA_CHECKSUM_EXCEPTION:
        return std::string("SVL_CLR_NET_CLRDBG_DATA_CHECKSUM_EXCEPTION");

    default:
        break;
    }

    // Get handle to ntdll.dll.
    HMODULE hNtDll = LoadLibrary( _T( "NTDLL.DLL" ) );

    DWORD dwRet = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        0,
        GetLastError(),
        MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
        (LPSTR)&lpszTemp,
        0,
        NULL
    );

    std::string errorMessage;
    if ( dwRet && lpszTemp ) {
        // Trim trailing CR/LF if present (original code removed last two chars).
        size_t len = lstrlenA(lpszTemp);
        if (len >= 2) {
            lpszTemp[len - 2] = '\0';
        }

        errorMessage = lpszTemp;

        for ( int i = 0; i < record->NumberParameters; ++i ) {
            std::stringstream paramPlaceholder;
            paramPlaceholder << "%" << ( i + 1 );

            std::stringstream paramValue;
            paramValue << record->ExceptionInformation[i];

            ReplaceAll( errorMessage, paramPlaceholder.str(), paramValue.str() );
        }
    }

    if ( lpszTemp ) {
        LocalFree( (HLOCAL)lpszTemp );
    }

    return errorMessage;
}

int Utility::ctol(const char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}
