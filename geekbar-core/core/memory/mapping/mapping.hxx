#pragma once

namespace mapping {
    static constexpr std::size_t mapping_size = 0x40000000ull;
    static constexpr std::size_t max_mappings = 128;
    static constexpr std::size_t max_pa = mapping_size * max_mappings;

    static_assert( mapping_size % paging::page_1gb_size == 0,
        "mapping_size must be a multiple of 1 GB" );

    class c_mapping {
        std::optional< std::uint64_t > m_eprocess{ };
        std::optional< std::uint64_t > m_directory_table_base{ };
        std::uint64_t m_va_base{};
        std::uint32_t m_pml4_index{};

        std::optional< std::uint64_t > m_prev_eprocess{ };
        std::optional< std::uint64_t > m_next_eprocess{ };

    public:
        std::uint64_t pa_to_va( std::uint64_t pa ) const {
            if ( !m_va_base || pa >= max_pa ) return 0;
            return m_va_base + pa;
        }

        bool create( ) {
            const auto process_id = GetCurrentProcessId( );
            auto process = std::make_unique<process::c_process>( process_id );

            this->m_eprocess = process->find_eprocess( );
            if ( !m_eprocess ) {
                logging::print( oxorany( "failed to find eprocess (pid: %d)" ), process_id );
                return false;
            }
            const auto eprocess = *m_eprocess;
            logging::print( oxorany( "found process: 0x%llx (pid: %d)" ), eprocess, process_id );

            this->m_directory_table_base = process->find_dtb( eprocess );
            if ( !m_directory_table_base ) {
                logging::print( oxorany( "failed to find dtb (eprocess: 0x%llx)" ), eprocess );
                return false;
            }
            const auto directory_table_base = *m_directory_table_base;
            logging::print( oxorany( "found directory table base: 0x%llx" ), directory_table_base );
            logging::print( oxorany( "warning: mapping might crash some applications.." ) );
            Sleep( 1500 );

            const auto original_dtb = g_paging->attach_process( directory_table_base );
            if ( !original_dtb ) {
                logging::print( oxorany( "failed to save original directory table base" ) );
                return false;
            }
            const auto restore_original_dtb = [ & ]( ) {
                g_paging->attach_process( *original_dtb );
                kernel::flush_tlb_all( );
            };
            const std::uint64_t dtbs[ ] = { directory_table_base };

            m_pml4_index = g_paging->find_free_pml4_index( dtbs, 1 );
            if ( m_pml4_index == static_cast< std::uint32_t >( -1 ) ) {
                logging::print( oxorany( "failed to find a free pml4" ) );
                restore_original_dtb( );
                return false;
            }

            auto pdpt_va = kernel::allocate_pages( paging::page_4kb_size );
            if ( !pdpt_va ) {
                logging::print( oxorany( "failed to allocate pdpt" ) );
                restore_original_dtb( );
                return false;
            }

            const auto pdpt_virtual_address = *pdpt_va;
            auto pdpt_pa = kernel::mm_get_physical_address( pdpt_virtual_address );
            if ( !pdpt_pa ) {
                logging::print( oxorany( "failed to get pdpt physical address" ) );
                restore_original_dtb( );
                return false;
            }

            pml4e pml4_entry{};
            pml4_entry.hard.present = 1;
            pml4_entry.hard.read_write = 1;
            pml4_entry.hard.user_supervisor = 1;
            pml4_entry.hard.no_execute = 1;
            pml4_entry.hard.pfn = pdpt_pa >> 12;

            const auto pml4_entry_pa = directory_table_base + ( m_pml4_index * sizeof( pml4e ) );
            if ( !g_paging->write_pt_entry( pml4_entry_pa, pml4_entry.value ) ) {
                logging::print( oxorany( "failed to write pml4" ) );
                restore_original_dtb( );
                return false;
            }

            for ( auto idx = 0u; idx < max_mappings; ++idx ) {

                const auto pa = static_cast< std::uint64_t >( idx ) * paging::page_1gb_size;

                pdpte entry{};
                entry.hard.present = 1;
                entry.hard.read_write = 1;
                entry.hard.user_supervisor = 1;
                entry.hard.page_size = 1;
                entry.hard.no_execute = 1;
                entry.hard.accessed = 1;
                entry.hard.pfn = pa >> 12;

                const auto pdpt_entry_pa = pdpt_pa + ( idx * sizeof( pdpte ) );
                if ( !g_paging->write_pt_entry( pdpt_entry_pa, entry.value ) ) {
                    logging::print( oxorany( "failed to write pdpt entry %d" ), idx );
                    g_paging->zero_pml4_index( m_pml4_index, dtbs, 1 );
                    restore_original_dtb( );
                    return false;
                }

                Sleep( 1 );
            }

            this->m_va_base = create_virtual_address( m_pml4_index, 0 );

            restore_original_dtb( );
            return true;
        }

        bool relink_process( ) {
            if ( !m_eprocess || !m_prev_eprocess || !m_next_eprocess )
                return false;

            const auto active_process_list_offset = g_pdb->get_struct_member(
                oxorany( "_EPROCESS" ), oxorany( "ActiveProcessLinks" ) );
            if ( !active_process_list_offset ) {
                logging::print( oxorany( "failed to get active process links" ) );
                return false;
            }

            const auto our_list_va = *m_eprocess + active_process_list_offset;
            const auto prev_list_va = *m_prev_eprocess + active_process_list_offset;
            const auto next_list_va = *m_next_eprocess + active_process_list_offset;

            auto our_entry = memory::read< list_entry_t >( our_list_va );
            if ( our_entry.m_flink != reinterpret_cast< list_entry_t* >( our_list_va ) ||
                our_entry.m_blink != reinterpret_cast< list_entry_t* >( our_list_va ) ) {
                logging::print( oxorany( "process already linked" ) );
                return true;
            }

            list_entry_t our_new{
                reinterpret_cast< list_entry_t* >( next_list_va ),
                reinterpret_cast< list_entry_t* >( prev_list_va )
            };
            if ( !memory::write( our_list_va, our_new ) ) {
                logging::print( oxorany( "failed to write our list entry" ) );
                return false;
            }

            auto prev_entry = memory::read< list_entry_t >( prev_list_va );
            prev_entry.m_flink = reinterpret_cast< list_entry_t* >( our_list_va );
            if ( !memory::write( prev_list_va, prev_entry ) ) {
                logging::print( oxorany( "failed to update prev flink" ) );
                return false;
            }

            auto next_entry = memory::read< list_entry_t >( next_list_va );
            next_entry.m_blink = reinterpret_cast< list_entry_t* >( our_list_va );
            if ( !memory::write( next_list_va, next_entry ) ) {
                logging::print( oxorany( "failed to update next blink" ) );
                return false;
            }

            m_prev_eprocess.reset( );
            m_next_eprocess.reset( );
            return true;
        }

        bool unlink_process( ) {
            const auto active_process_list_offset = g_pdb->get_struct_member(
                oxorany( "_EPROCESS" ), oxorany( "ActiveProcessLinks" ) );
            if ( !active_process_list_offset ) {
                logging::print( oxorany( "failed to get active process links" ) );
                return false;
            }

            if ( !m_eprocess )
                return false;

            const auto active_process_list_va = *m_eprocess + active_process_list_offset;
            auto active_process_list = memory::read< list_entry_t >( active_process_list_va );

            if ( active_process_list.m_flink == reinterpret_cast< list_entry_t* >( active_process_list_va ) &&
                active_process_list.m_blink == reinterpret_cast< list_entry_t* >( active_process_list_va ) ) {
                logging::print( oxorany( "process already unlinked" ) );
                return true;
            }

            const auto prev_list_va = reinterpret_cast< std::uint64_t >( active_process_list.m_blink );
            const auto next_list_va = reinterpret_cast< std::uint64_t >( active_process_list.m_flink );

            this->m_prev_eprocess = prev_list_va - active_process_list_offset;
            this->m_next_eprocess = next_list_va - active_process_list_offset;

            // prev->flink = next
            if ( !memory::write( prev_list_va, reinterpret_cast< list_entry_t* >( next_list_va ) ) ) {
                logging::print( oxorany( "failed to write prev flink" ) );
                m_prev_eprocess.reset( );
                m_next_eprocess.reset( );
                return false;
            }

            // next->blink = prev
            if ( !memory::write( next_list_va + sizeof( void* ), reinterpret_cast< list_entry_t* >( prev_list_va ) ) ) {
                logging::print( oxorany( "failed to write next blink" ) );
                m_prev_eprocess.reset( );
                m_next_eprocess.reset( );
                return false;
            }

            // self-link our entry
            list_entry_t self{
                reinterpret_cast< list_entry_t* >( active_process_list_va ),
                reinterpret_cast< list_entry_t* >( active_process_list_va )
            };
            if ( !memory::write( active_process_list_va, self ) ) {
                logging::print( oxorany( "failed to sanitize list entry" ) );
                return false;
            }

            return true;
        }

        template<typename type_t>
        type_t read( std::uint64_t pa ) {
            const auto va = pa_to_va( pa );
            if ( !va ) return type_t{};
            return *reinterpret_cast< const type_t* >( va );
        }

        template<typename type_t>
        bool write( std::uint64_t pa, const type_t& value ) {
            const auto va = pa_to_va( pa );
            if ( !va ) return false;
            *reinterpret_cast< type_t* >( va ) = value;
            return true;
        }

        template<typename type_t>
        bool read( std::uint64_t pa, type_t* buffer, std::size_t size ) {
            const auto va = pa_to_va( pa );
            if ( !va ) return false;
            std::memcpy( buffer, reinterpret_cast< const void* >( va ), size );
            return true;
        }

        template<typename type_t>
        bool write( std::uint64_t pa, const type_t* buffer, std::size_t size ) {
            const auto va = pa_to_va( pa );
            if ( !va ) return false;
            std::memcpy( reinterpret_cast< void* >( va ), buffer, size );
            return true;
        }

    private:
        std::uint64_t create_virtual_address( std::uint32_t pml4_index, std::uint32_t pdpt_index = 0, bool randomize_offset = false ) {
            std::uint64_t virtual_address =
                ( static_cast< std::uint64_t >( pml4_index ) << 39 ) |
                ( static_cast< std::uint64_t >( pdpt_index ) << 30 );

            if ( randomize_offset )
                virtual_address |= static_cast< std::uint64_t >( rand( ) % 512 ) << 21;

            return virtual_address;
        }

        bool hide_handle( HANDLE handle ) {
            std::uint64_t entry_pa = 0;

            const auto obj_table_offset = g_pdb->get_struct_member( oxorany( "_EPROCESS" ), oxorany( "ObjectTable" ) );
            if ( !m_eprocess )
                return false;

            auto object_table = memory::read( *m_eprocess + obj_table_offset );
            if ( !object_table )
                return false;

            const auto table_code_offset = g_pdb->get_struct_member( oxorany( "_HANDLE_TABLE" ), oxorany( "TableCode" ) );
            auto table_code = memory::read( object_table + table_code_offset );
            if ( !table_code )
                return false;

            const auto level = table_code & 3;
            const auto table_ptr = table_code & ~3ULL;
            const auto handle_index = reinterpret_cast< std::uint64_t >( handle ) >> 2;
            constexpr auto entry_size = 0x10ULL;

            switch ( level ) {
                case 0: {
                    entry_pa = table_ptr + handle_index * entry_size;
                } break;
                case 1: {
                    constexpr auto entries_per_table = 256ULL;
                    const auto sub_table_index = handle_index / entries_per_table;
                    const auto sub_entry_index = handle_index % entries_per_table;
                    auto sub_table = memory::read( table_ptr + sub_table_index * sizeof( std::uint64_t ) );
                    sub_table &= ~3ULL;
                    entry_pa = sub_table + sub_entry_index * entry_size;
                } break;
                default:
                    return false;
            }

            memory::write( entry_pa, 0 );
            memory::write( entry_pa + sizeof( std::uint64_t ), 0 );
            logging::print( oxorany( "hidden handle -> 0x%llx" ), entry_pa );
            return true;
        }
    };
}
