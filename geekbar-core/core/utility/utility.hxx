#pragma once

#pragma once

#include <mutex>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <string>
#include <intrin.h>

namespace logging {
    struct rgb_t { int r , g , b; };

    // Helper functions
    inline rgb_t lerp_rgb ( const rgb_t& a , const rgb_t& b , float t ) {
        if ( t <= 0.0f ) return a;
        if ( t >= 1.0f ) return b;
        return {
            a.r + ( int ) ( ( b.r - a.r ) * t ),
            a.g + ( int ) ( ( b.g - a.g ) * t ),
            a.b + ( int ) ( ( b.b - a.b ) * t )
        };
    }

    inline float smooth_step ( float t ) {
        if ( t <= 0.0f ) return 0.0f;
        if ( t >= 1.0f ) return 1.0f;
        return t * t * ( 3.0f - 2.0f * t );
    }

    template<typename... Args>
    inline void print ( const char* format , Args... args ) {
        static std::mutex print_mutex;
        std::lock_guard<std::mutex> lock ( print_mutex );
        static constexpr rgb_t k_grad_a = { 7, 62, 100 };
        static constexpr rgb_t k_grad_b = { 44, 187, 232 };
        static constexpr rgb_t k_grad_c = { 16, 130, 198 };

        std::time_t now = std::time ( nullptr );
        std::tm local_tm {};
        localtime_s ( &local_tm , &now );
        char ts [ 32 ] = {};
        std::strftime ( ts , sizeof ( ts ) , "%H:%M:%S %d/%m/%Y" , &local_tm );

        char msg [ 4096 ];
        int n = snprintf ( msg , sizeof ( msg ) , format , args... );
        if ( n < 0 || n >= ( int ) sizeof ( msg ) ) {
            const std::string prefix = std::string ( "[ " ) + ts + " ] [ emulated.vip ]: ";
            const size_t total = prefix.size ( );
            for ( size_t i = 0; i < total; ++i ) {
                float t = ( total > 1 ) ? ( float ) i / ( float ) ( total - 1 ) : 0.0f;
                rgb_t c = {};
                if ( t < 0.5f ) {
                    c = lerp_rgb ( k_grad_a , k_grad_b , smooth_step ( t * 2.0f ) );
                }
                else {
                    c = lerp_rgb ( k_grad_b , k_grad_c , smooth_step ( ( t - 0.5f ) * 2.0f ) );
                }
                printf ( "\x1b[38;2;%d;%d;%dm%c" , c.r , c.g , c.b , prefix [ i ] );
            }
            printf ( format , args... );
            printf ( "\x1b[0m\n" );
            return;
        }

        size_t len = strlen ( msg );
        while ( len && ( msg [ len - 1 ] == '\n' || msg [ len - 1 ] == '\r' ) ) msg [ --len ] = '\0';

        const std::string prefix = std::string ( "[ " ) + ts + " ] [ emulated.vip ]: ";
        const size_t total = prefix.size ( );
        for ( size_t i = 0; i < total; ++i ) {
            float t = ( total > 1 ) ? ( float ) i / ( float ) ( total - 1 ) : 0.0f;
            rgb_t c = {};
            if ( t < 0.5f ) {
                c = lerp_rgb ( k_grad_a , k_grad_b , smooth_step ( t * 2.0f ) );
            }
            else {
                c = lerp_rgb ( k_grad_b , k_grad_c , smooth_step ( ( t - 0.5f ) * 2.0f ) );
            }
            printf ( "\x1b[38;2;%d;%d;%dm%c" , c.r , c.g , c.b , prefix [ i ] );
        }
        printf ( "\x1b[97m%s" , msg );
        printf ( "\x1b[0m\n" );
    }
}

namespace utility {
    bool is_physical_address_valid( std::uint64_t pa, std::size_t size ) {
        static const std::uint64_t physical_mask = [ ]( ) -> std::uint64_t {
            int regs[ 4 ]{};
            __cpuid( regs, 0x80000000 );
            unsigned max_ext = static_cast< unsigned >( regs[ 0 ] );
            unsigned phys_bits = 36;
            if ( max_ext >= 0x80000008 ) {
                __cpuid( regs, 0x80000008 );
                unsigned b = regs[ 0 ] & 0xFF;
                if ( b >= 32 && b <= 52 )
                    phys_bits = b;
            }
            return ( phys_bits >= 63 ) ? ~0ULL : ( ( 1ULL << phys_bits ) - 1ULL );
            }( );

        if ( ( pa & ~physical_mask ) != 0 )
            return false;

        const auto end_pa = pa + ( size - 1 );
        if ( ( end_pa & ~physical_mask ) != 0 )
            return false;

        return true;
    }

    void gen_rnd_str( wchar_t* random_str ) {
        static std::mt19937 rng( std::random_device{}( ) );
        std::uniform_int_distribution<size_t> len_dist( 8, 19 );
        size_t length = len_dist( rng );

        std::uniform_int_distribution<int> char_type( 0, 2 );
        std::uniform_int_distribution<int> alpha( 0, 25 );
        std::uniform_int_distribution<int> digit( 0, 9 );

        for ( size_t i = 0; i < length; ++i ) {
            switch ( char_type( rng ) ) {
                case 0:
                    random_str[ i ] = L'A' + alpha( rng );
                    break;
                case 1:
                    random_str[ i ] = L'a' + alpha( rng );
                    break;
                case 2:
                    random_str[ i ] = L'0' + digit( rng );
                    break;
            }
        }
        random_str[ length ] = L'\0';
    }

    bool enable_privilege( const wchar_t* priv_name ) {
        HANDLE token = nullptr;
        if ( !OpenProcessToken( GetCurrentProcess( ),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token ) )
            return false;

        LUID luid{};
        if ( !LookupPrivilegeValueW( nullptr, priv_name, &luid ) ) {
            CloseHandle( token );
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[ 0 ].Luid = luid;
        tp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError( ERROR_SUCCESS );
        bool result = AdjustTokenPrivileges( token, FALSE, &tp, sizeof( tp ),
            nullptr, nullptr ) && GetLastError( ) != ERROR_NOT_ALL_ASSIGNED;
        CloseHandle( token );
        return result;
    }

    std::uint32_t find_pid( std::wstring target_process ) {
        auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if ( snapshot == INVALID_HANDLE_VALUE )
            return 0;

        PROCESSENTRY32W entry{ .dwSize = sizeof( entry ) };
        std::uint32_t result = 0;

        if ( Process32FirstW( snapshot, &entry ) ) {
            do {
                // Process image names are case-insensitive on Windows.  Use the
                // ordinal comparison so this does not depend on the user's locale.
                if ( CompareStringOrdinal( target_process.c_str( ), -1,
                    entry.szExeFile, -1, TRUE ) == CSTR_EQUAL ) {
                    result = entry.th32ProcessID;
                    break;
                }
            } while ( Process32NextW( snapshot, &entry ) );
        }

        CloseHandle( snapshot );
        return result;
    }

    std::string add_commas( std::uint64_t n ) {
        auto s = std::to_string( n );
        auto pos = ( int )s.size( ) - 3;
        while ( pos > 0 ) {
            s.insert( pos, "," );
            pos -= 3;
        }
        return s;
    }

    std::string format_process_name( const std::wstring& target_process ) {
        std::string name( target_process.begin( ), target_process.end( ) );

        auto dot = name.find( '.' );
        if ( dot != std::string::npos )
            name = name.substr( 0, dot );

        auto dash = name.find( '-' );
        if ( dash != std::string::npos )
            name = name.substr( 0, dash );

        std::size_t start = std::string::npos;
        for ( std::size_t i = 0; i < name.size( ); ++i ) {
            if ( std::isupper( static_cast< unsigned char >( name[ i ] ) ) ) {
                if ( start == std::string::npos ) {
                    start = i;
                }
                else {
                    name = name.substr( start, i - start );
                    break;
                }
            }
        }

        if ( start != std::string::npos && start > 0 )
            name = name.substr( start );

        std::transform( name.begin( ), name.end( ), name.begin( ),
            [ ]( unsigned char c ) { return std::tolower( c ); } );

        return name;
    }
}
