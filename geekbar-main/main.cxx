#include <deps/includes.h>

int main( ) {
    SetConsoleTitleA( oxorany( "geekbar-driverless" ) );

    bypass::options_t options{};
    options.clean_unloaded_drivers = false;
    options.clear_usn_journal = true;
    bypass::set_options( options );

    bypass::initialize( );
    if ( !bypass::create( ) ) {
        logging::print( oxorany( "failed to create bypass." ) );
        return std::getchar( );
    }

    if ( !bypass::target::setup( oxorany( L"notepad.exe" ) ) ) {
        logging::print( oxorany( "failed to create process." ) );
        return std::getchar( );
    }

    bypass::target::benchmark_rps( );

    const auto magic = bypass::read<std::uint16_t>( bypass::target::m_base_address );
    logging::print( oxorany( "pe header=0x%llx, magic=0x%04X" ),
        bypass::target::m_base_address, magic );

    return std::getchar( );
}
