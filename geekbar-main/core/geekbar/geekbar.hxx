#pragma once



namespace bypass {
    struct options_t {
        bool clean_unloaded_drivers; // cleans vuln loaded ( only disable if u bluescreen )
        bool clear_usn_journal; // cleans usn journal logs of vuln and some stuff from loader.
    };

    void set_options( const options_t& opts );
    const options_t& get_options( );

    void initialize( );
    bool create( );

    namespace target {
        extern std::uint32_t m_process_pid;
        extern std::uint64_t m_eprocess;
        extern std::uint64_t m_process_peb;
        extern std::uint64_t m_base_address;
        extern std::uint64_t m_directory_table_base;

        bool setup( std::wstring process_name );

        std::uint64_t translate_linear( std::uint64_t virt_addr, std::uint32_t* page_size = nullptr );
        bool read_memory( std::uint64_t va, void* buf, std::size_t size );
        bool write_memory( std::uint64_t va, void* buf, std::size_t size );
        void benchmark_rps( );
    }

    template <typename ret_t = std::uint64_t, typename addr_t>
    ret_t read( addr_t va ) {
        std::uint64_t va64;
        if constexpr ( std::is_pointer_v<addr_t> )
            va64 = reinterpret_cast< std::uint64_t >( va );
        else if constexpr ( std::is_integral_v<addr_t> )
            va64 = static_cast< std::uint64_t >( va );
        else
            static_assert( std::is_pointer_v<addr_t> || std::is_integral_v<addr_t>,
                "addr_t must be pointer or integral" );
        ret_t ret{};
        target::read_memory( va64, &ret, sizeof( ret ) );
        return ret;
    }

    template <typename val_t, typename addr_t>
    bool write( addr_t va, val_t val ) {
        std::uint64_t va64;
        if constexpr ( std::is_pointer_v<addr_t> )
            va64 = reinterpret_cast< std::uint64_t >( va );
        else if constexpr ( std::is_integral_v<addr_t> )
            va64 = static_cast< std::uint64_t >( va );
        else
            static_assert( std::is_pointer_v<addr_t> || std::is_integral_v<addr_t>,
                "addr_t must be pointer or integral" );

        return target::write_memory( va64, &val, sizeof( val_t ) );
    }
}
