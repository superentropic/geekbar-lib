#pragma once

namespace syscall {
    class c_syscall {
    public:
        bool setup( ) {
            const auto ke_service_descriptor_table =
                g_pdb->get_symbol_address( oxorany( "KeServiceDescriptorTable" ) );
            if ( !ke_service_descriptor_table ) {
                logging::print( oxorany( "failed to resolve service descriptor" ) );
                return false;
            }

            std::uint64_t ssdt_data[ 4 ]{};
            if ( !memory::read_virtual( ke_service_descriptor_table, ssdt_data, sizeof( ssdt_data ) ) ) {
                logging::print( oxorany( "failed to read service descriptor" ) );
                return false;
            }

            m_ssdt_base = ssdt_data[ 0 ];
            const auto count = ssdt_data[ 2 ];
            logging::print( oxorany( "syscall base: 0x%llx (count=%llu)" ), m_ssdt_base, count );

            const auto nt_create_event =
                g_pdb->get_symbol_address( oxorany( "NtCreateEvent" ) );
            if ( !nt_create_event ) {
                logging::print( oxorany( "failed to resolve create event" ) );
                return false;
            }

            std::vector<std::uint32_t> table( count );
            if ( !memory::read_virtual( m_ssdt_base, table.data( ), count * sizeof( std::uint32_t ) ) ) {
                logging::print( oxorany( "failed to read ssdt table" ) );
                return false;
            }

            const auto target_rva = ( int )( nt_create_event - m_ssdt_base ) << 4;
            for ( std::size_t idx = 0; idx < count; idx++ ) {
                if ( ( table[ idx ] & 0xfffffff0 ) != ( target_rva & 0xfffffff0 ) )
                    continue;

                this->m_saved_entry = table[ idx ];
                this->m_entry_va = m_ssdt_base + idx * sizeof( std::uint32_t );
                this->m_entry_pa = g_paging->translate_linear( m_entry_va );
                break;
            }

            if ( !m_entry_pa ) {
                logging::print( oxorany( "failed to find syscall entry" ) );
                return false;
            }

            logging::print( oxorany( "syscall complete: 0x%llx (original=0x%08x)\n" ),
                m_entry_va, m_saved_entry );
            return true;
        }

        template<typename ret_t = std::uint64_t,
            typename a1_t = void*, typename a2_t = void*,
            typename a3_t = void*, typename a4_t = void*,
            typename a5_t = void*, typename a6_t = void*,
            typename a7_t = void*, typename a8_t = void*,
            typename a9_t = void*, typename a10_t = void*>
        ret_t call_kernel( std::uint64_t func,
            a1_t  a1 = {}, a2_t  a2 = {}, a3_t  a3 = {},
            a4_t  a4 = {}, a5_t  a5 = {}, a6_t  a6 = {},
            a7_t  a7 = {}, a8_t  a8 = {}, a9_t  a9 = {},
            a10_t a10 = {} ) {

            if ( !m_entry_pa ) {
                logging::print( oxorany( "syscall not initialized" ) );
                if constexpr ( std::is_void_v<ret_t> ) return;
                else return ret_t{};
            }

            std::unique_lock lock( m_lock );
            const auto new_rva = ( int )( func - m_ssdt_base ) << 4;
            auto new_entry = ( new_rva & 0xfffffff0 ) | 0x0;

            if ( !memory::write_physical( m_entry_pa, &new_entry, sizeof( new_entry ) ) ) {
                if constexpr ( std::is_void_v<ret_t> ) return;
                else return ret_t{};
            }

            using fn_t = void* ( __stdcall* )(
                a1_t, a2_t, a3_t, a4_t, a5_t,
                a6_t, a7_t, a8_t, a9_t, a10_t );

            auto nt_fn = reinterpret_cast< fn_t >(
                GetProcAddress( GetModuleHandleA( oxorany( "ntdll.dll" ) ), oxorany( "NtCreateEvent" ) ) );

            void* result = nullptr;
            if ( nt_fn )
                result = nt_fn( a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 );

            memory::write_physical( m_entry_pa, &m_saved_entry, sizeof( m_saved_entry ) );

            if constexpr ( std::is_void_v<ret_t> ) return;
            else return reinterpret_cast< ret_t >( result );
        }

    private:
        std::shared_mutex m_lock{};
        std::uint64_t     m_ssdt_base{ 0 };
        std::uint64_t     m_entry_va{ 0 };
        std::uint64_t     m_entry_pa{ 0 };
        std::uint32_t     m_saved_entry{ 0 };
    };
}