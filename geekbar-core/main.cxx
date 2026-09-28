#include <deps/includes.h>

namespace bypass {
    struct options_t {
        bool clean_unloaded_drivers = true;
        bool clear_usn_journal = true;
    };

    static options_t g_options{};

    void set_options( const options_t& opts ) {
        g_options = opts;
    }

    const options_t& get_options( ) {
        return g_options;
    }

    void initialize( ) {
        auto std_handle = GetStdHandle( STD_OUTPUT_HANDLE );
        DWORD mode;
        GetConsoleMode( std_handle, &mode );
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode( std_handle, mode );

        SetUnhandledExceptionFilter( crash::crash_handler );
        SetConsoleCtrlHandler(
            reinterpret_cast< PHANDLER_ROUTINE >( crash::unload_handler ),
            true
        );
    }

	bool create( ) {
        logging::print( oxorany( "downloading ntoskrnl pdb..." ) );
        if ( !g_pdb->load( ) ) {
            logging::print( oxorany( "failed to load pdb" ) );
            return false;
        }

        if ( !g_service->create( ) ) {
            logging::print( oxorany( "failed to setup service" ) );
            g_service->unload( );
            return false;
        }

        if ( !g_driver->initialize( ) ) {
            logging::print( oxorany( "failed to setup driver" ) );
            g_service->unload( );
            return false;
        }

        if ( !g_paging->setup( ) ) {
            logging::print( oxorany( "failed to setup paging" ) );
            g_service->unload( );
            g_driver->unload( );
            return false;
        }

        if ( !g_syscall->setup( ) ) {
            logging::print( oxorany( "failed to setup syscall" ) );
            g_service->unload( );
            g_driver->unload( );
            return false;
        }

        if ( !g_service->cleanup( ) ) {
            logging::print( oxorany( "failed to clean service" ) );
            g_service->unload( );
            g_driver->unload( );
            return false;
        }

        if ( !g_mapping->create( ) ) {
            logging::print( oxorany( "failed to create mappings" ) );
            g_service->unload( );
            g_driver->unload( );
            return false;
        }

        g_service->unload( );
        g_driver->unload( );

        memory::m_read_physical = [ ]( std::uint64_t addr, void* buffer, std::size_t size ) -> bool {
            return g_mapping->read( addr, buffer, size );
            };

        memory::m_write_physical = [ ]( std::uint64_t addr, void* buffer, std::size_t size ) -> bool {
            return g_mapping->write( addr, buffer, size );
            };

        if ( g_options.clean_unloaded_drivers ) {
            if ( !g_service->clean_unloaded_driver( ) ) {
                logging::print( oxorany( "failed to clean unloaded driver" ) );
                return false;
            }
        }

        // not needed but it's better to be safe than sorry
        //if ( !g_mapping->unlink_process( ) ) {
        //    logging::print( oxorany( "failed to unlink process" ) );
        //    return false;
        //}

        if ( g_options.clear_usn_journal ) {
            if ( !g_usn_journal->clear( ) ) {
                logging::print( oxorany( "failed to clean usn journal" ) );
                return false;
            }
        }

        return true;
	}

    namespace target {
        extern std::uint32_t m_process_pid{ };
        extern std::uint64_t m_eprocess{ };
        extern std::uint64_t m_process_peb{ };
        extern std::uint64_t m_base_address{ };
        extern std::uint64_t m_directory_table_base{ };

        struct batch_read_t {
            std::uint64_t va;
            void* buf;
            std::size_t   size;
            bool          success;
        };

        struct pt_cache_entry_t {
            std::uint64_t phys_addr = 0;
            std::uint64_t raw = 0;
        };

        static constexpr std::size_t cache_size = 512;
        static constexpr std::uint64_t cache_mask = cache_size - 1;

        alignas( 64 ) pt_cache_entry_t m_pml4_cache[ 512 ]{};
        alignas( 64 ) pt_cache_entry_t m_pdpt_cache[ 512 ]{};
        alignas( 64 ) pt_cache_entry_t m_pd_cache[ 512 ]{};
        alignas( 64 ) pt_cache_entry_t m_pt_cache[ 512 ]{};

        bool setup ( std::wstring process_name ) {
            auto formatted_name = utility::format_process_name ( process_name );
            logging::print ( oxorany ( "press f2 once inside %s" ) , formatted_name.c_str ( ) );

            while ( !( GetAsyncKeyState ( VK_F2 ) & 0x8000 ) ) {
                Sleep ( 100 );
            }

            m_process_pid = utility::find_pid ( process_name );
            if ( !m_process_pid ) {
                logging::print( oxorany( "could not find target process: %s" ), formatted_name.c_str( ) );
                return false;
            }


            auto process = std::make_unique<process::c_process> ( m_process_pid );
            const auto eprocess = process->find_eprocess( );
            if ( !eprocess ) {
                logging::print( oxorany( "could not find target process object (pid: %d)" ), m_process_pid );
                return false;
            }
            m_eprocess = *eprocess;
            logging::print ( oxorany ( "process: 0x%llx" ) , m_eprocess );

            const auto base_address = process->find_base_address( m_eprocess );
            if ( !base_address ) {
                logging::print ( oxorany ( "could not find base address" ) );
                return false;
            }
            m_base_address = *base_address;
            logging::print ( oxorany ( "base address: 0x%llx" ) , m_base_address );

            const auto process_peb = process->find_peb( m_eprocess );
            if ( !process_peb ) {
                logging::print ( oxorany ( "could not find process peb" ) );
                return false;
            }
            m_process_peb = *process_peb;
            logging::print ( oxorany ( "process peb: 0x%llx" ) , m_process_peb );

            m_directory_table_base = g_paging->find_dtb ( m_base_address , m_process_peb );
            if ( !m_directory_table_base ) {
                logging::print ( oxorany ( "could not find directory table base" ) );
                return false;
            }

            logging::print ( oxorany ( "found %s successfully!\n" ) , formatted_name.c_str ( ) );
            return true;
        }


        std::uint64_t translate_linear( std::uint64_t virt_addr, std::uint32_t* page_size = nullptr ) {
            const virt_addr_t va{ .value = virt_addr };

            const auto pml4_pa = m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) );
            auto& pml4_slot = m_pml4_cache[ va.pml4e_index ];
            if ( pml4_slot.phys_addr != pml4_pa ) [[unlikely]] {
                const auto entry = g_paging->read_pt_entry<pml4e>( pml4_pa );
                if ( !entry || !entry->hard.present ) return 0;
                pml4_slot = { pml4_pa, entry->hard.pfn << 12 };
            }

            const auto pdpt_pa = pml4_slot.raw + ( va.pdpte_index * sizeof( pdpte ) );
            const auto pdpt_idx = ( va.pml4e_index << 9 ) | va.pdpte_index;
            auto& pdpt_slot = m_pdpt_cache[ pdpt_idx & cache_mask ];
            if ( pdpt_slot.phys_addr != pdpt_pa ) [[unlikely]] {
                const auto entry = g_paging->read_pt_entry<pdpte>( pdpt_pa );
                if ( !entry || !entry->hard.present ) return 0;
                if ( entry->hard.page_size ) [[unlikely]] {
                    if ( page_size ) *page_size = paging::page_1gb_size;
                    return ( entry->hard.pfn << 12 ) + ( virt_addr & paging::page_1gb_mask );
                }
                pdpt_slot = { pdpt_pa, entry->hard.pfn << 12 };
            }

            const auto pd_pa = pdpt_slot.raw + ( va.pde_index * sizeof( pde ) );
            const auto pd_idx = ( va.pdpte_index << 9 ) | va.pde_index;
            auto& pd_slot = m_pd_cache[ pd_idx & cache_mask ];
            if ( pd_slot.phys_addr != pd_pa ) [[unlikely]] {
                const auto entry = g_paging->read_pt_entry<pde>( pd_pa );
                if ( !entry || !entry->hard.present ) return 0;
                if ( entry->hard.page_size ) [[likely]] {
                    if ( page_size ) *page_size = paging::page_2mb_size;
                    return ( entry->hard.pfn << 12 ) + ( virt_addr & paging::page_2mb_mask );
                }
                pd_slot = { pd_pa, entry->hard.pfn << 12 };
            }

            const auto pt_pa = pd_slot.raw + ( va.pte_index * sizeof( pte ) );
            const auto pt_idx = ( va.pde_index << 9 ) | va.pte_index;
            auto& pt_slot = m_pt_cache[ pt_idx & cache_mask ];
            if ( pt_slot.phys_addr != pt_pa ) [[unlikely]] {
                const auto entry = g_paging->read_pt_entry<pte>( pt_pa );
                if ( !entry || !entry->hard.present ) return 0;
                pt_slot = { pt_pa, entry->hard.pfn << 12 };
            }

            if ( page_size ) *page_size = paging::page_4kb_size;
            return pt_slot.raw + ( virt_addr & paging::page_4kb_mask );
        }

        bool read_memory( std::uint64_t va, void* buf, std::size_t size ) {
            auto phys = translate_linear( va );
            if ( !phys ) return false;
            return memory::read_physical( phys, buf, size );
        }

        bool write_memory( std::uint64_t va, void* buf, std::size_t size ) {
            auto phys = translate_linear( va );
            if ( !phys ) return false;
            return memory::write_physical( phys, buf, size );
        }

        void benchmark_rps( ) {
            auto read_buffer = 0ull;
            auto ops = 0ull;

            for ( auto i = 0; i < 10000; i++ )
                read_memory( m_base_address + 0x1000, &read_buffer,
                        sizeof( std::uint64_t ) );

            auto start = std::chrono::steady_clock::now( );
            auto deadline = start + std::chrono::seconds( 1 );

            while ( std::chrono::steady_clock::now( ) < deadline ) {
                for ( auto i = 0; i < 1000; i++ ) {
                    if ( read_memory( m_base_address + 0x1000, &read_buffer,
                            sizeof( std::uint64_t ) ) )
                        ++ops;
                }
            }

            auto elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now( ) - start ).count( );
            auto rps = static_cast< std::uint64_t >(
                static_cast< double >( ops ) / elapsed );

            logging::print( oxorany( "%s rps in %.fs" ),
                utility::add_commas( rps ).c_str( ),
                elapsed );
        }
    }
}
