#pragma once

namespace process {
    class c_process {
    public:
        c_process( std::uint32_t target_pid ) : m_target_pid( target_pid ) { }

        std::optional<std::uint64_t>
            find_eprocess( ) const {
            const auto list_head = g_pdb->get_symbol_address(
                oxorany( "PsActiveProcessHead" )
            );
            if ( !list_head )
                return std::nullopt;

            const auto links_offset = get_links_offset( );
            const auto pid_offset = get_pid_offset( );
            if ( !links_offset || !pid_offset )
                return std::nullopt;

            std::uint64_t current = 0;
            if ( !memory::read_virtual( list_head, &current, sizeof( current ) ) )
                return std::nullopt;

            for ( auto idx = 0;
                current && current != list_head && idx < 0x1000;
                ++idx ) {
                const auto eprocess = current - *links_offset;

                std::uint64_t cur_pid = 0;
                if ( !memory::read_virtual( eprocess + *pid_offset,
                    &cur_pid, sizeof( cur_pid ) ) )
                    break;

                if ( static_cast< std::uint32_t >( cur_pid ) == this->m_target_pid )
                    return eprocess;

                if ( !memory::read_virtual( current, &current, sizeof( current ) ) )
                    break;
            }

            logging::print( oxorany( "could not find process." ) );
            return std::nullopt;
        }

        std::optional<std::uint64_t>
            find_peb( std::uint64_t eprocess ) const {
            if ( !eprocess ) return std::nullopt;

            const auto offset = get_peb_offset( );
            if ( !offset ) return std::nullopt;

            std::uint64_t peb = 0;
            if ( !memory::read_virtual( eprocess + *offset, &peb, sizeof( peb ) ) )
                return std::nullopt;

            return peb ? std::optional<std::uint64_t>{ peb } : std::nullopt;
        }

        std::optional<std::uint64_t>
            find_base_address( std::uint64_t eprocess ) const {
            if ( !eprocess ) return std::nullopt;

            const auto offset = get_section_base_offset( );
            if ( !offset ) return std::nullopt;

            std::uint64_t base = 0;
            if ( !memory::read_virtual( eprocess + *offset, &base, sizeof( base ) ) )
                return std::nullopt;

            return base ? std::optional<std::uint64_t>{ base } : std::nullopt;
        }

        std::optional<std::uint64_t>
            find_dtb( std::uint64_t eprocess ) const {
            if ( !eprocess ) return std::nullopt;

            const auto offset = get_dtb_offset( );
            if ( !offset ) return std::nullopt;

            std::uint64_t dtb = 0;
            if ( !memory::read_virtual( eprocess + *offset, &dtb, sizeof( dtb ) ) )
                return std::nullopt;

            const auto aligned = dtb & ~0xFull;
            return aligned ? std::optional<std::uint64_t>{ aligned } : std::nullopt;
        }

    private:
        std::uint32_t m_target_pid = 0;
        mutable std::uint64_t m_links_offset = 0;
        mutable std::uint64_t m_pid_offset = 0;
        mutable std::uint64_t m_peb_offset = 0;
        mutable std::uint64_t m_section_base_offset = 0;
        mutable std::uint64_t m_dtb_offset = 0;

        std::optional<std::uint64_t> get_links_offset( ) const {
            if ( !m_links_offset )
                m_links_offset = g_pdb->get_struct_member(
                    oxorany( "_EPROCESS" ), oxorany( "ActiveProcessLinks" ) );
            return m_links_offset
                ? std::optional<std::uint64_t>{ m_links_offset } : std::nullopt;
        }

        std::optional<std::uint64_t> get_pid_offset( ) const {
            if ( !m_pid_offset )
                m_pid_offset = g_pdb->get_struct_member(
                    oxorany( "_EPROCESS" ), oxorany( "UniqueProcessId" ) );
            return m_pid_offset
                ? std::optional<std::uint64_t>{ m_pid_offset } : std::nullopt;
        }

        std::optional<std::uint64_t> get_peb_offset( ) const {
            if ( !m_peb_offset )
                m_peb_offset = g_pdb->get_struct_member(
                    oxorany( "_EPROCESS" ), oxorany( "Peb" ) );
            return m_peb_offset
                ? std::optional<std::uint64_t>{ m_peb_offset } : std::nullopt;
        }

        std::optional<std::uint64_t> get_section_base_offset( ) const {
            if ( !m_section_base_offset )
                m_section_base_offset = g_pdb->get_struct_member(
                    oxorany( "_EPROCESS" ), oxorany( "SectionBaseAddress" ) );
            return m_section_base_offset
                ? std::optional<std::uint64_t>{ m_section_base_offset } : std::nullopt;
        }

        std::optional<std::uint64_t> get_dtb_offset( ) const {
            if ( !m_dtb_offset )
                m_dtb_offset = g_pdb->get_struct_member(
                    oxorany( "_KPROCESS" ), oxorany( "DirectoryTableBase" ) );
            return m_dtb_offset
                ? std::optional<std::uint64_t>{ m_dtb_offset } : std::nullopt;
        }
    };
}