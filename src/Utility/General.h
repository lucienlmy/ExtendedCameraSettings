#pragma once

namespace Utility {
    HMODULE GetActiveModule();

    std::string GetModuleName( HMODULE hModule );

    std::string GetWorkingDirectory();

    std::string GetShortTimeString();

    bool FileExists( std::string fileName );

    std::string GetFilenameWithoutPath( const std::string& string, const bool removeExtension );

    void SplitString( std::string str, std::string splitBy, std::vector<std::string>& tokens );

    void ReplaceAll( std::string& str, const std::string& from, const std::string& to );

    void ToLower( std::string& str );

    unsigned int GetHashKey( std::string str );

    unsigned int StringToHash( std::string str );

    std::string HexString( BYTE* data, int len, bool idaStyle = false );

    bool IsCanonicalAddress( uintptr_t Address );

    bool IsMemoryReadable( LPCVOID lpcPtr );

    HMODULE GetModuleBase( PBYTE address, bool checkMappedModule );

    HMODULE GetModuleBase( PBYTE address, size_t& moduleSize, bool checkMappedModule );

    PVOID GetSectionBase( HMODULE moduleBase, const std::string& sectionName, size_t& sectionSize );

    std::string GetFriendlyErrorMessage( EXCEPTION_RECORD* record );

    int ctol( char c );

    template<typename ... Args>
    std::string FormatString( const std::string& format, Args ... args ) {
        size_t size = snprintf( nullptr, 0, format.c_str(), args ... ) + 1;
        std::unique_ptr<char[]> buf( new char[size] );
        snprintf( buf.get(), size, format.c_str(), args ... );
        return std::string( buf.get(), buf.get() + size - 1 );
    }
};
