#pragma once

namespace cache {
    list_entry_t* read_list_entry( std::uint64_t address ) {
        list_entry_t* entry = nullptr;
        memory::read_virtual( address, &entry, sizeof( entry ) );
        return entry;
    }

    struct hash_bucket_entry_t {
        list_entry_t* m_flink;
        unicode_string_t m_driver_name;
    };

    piddb_cache_entry_t* lookup_piddb_entry( avl_table_t* table, std::uint32_t timestamp, const wchar_t* name ) {
        wchar_t name_with_ext[ 32 ]{};
        std::wcscat( name_with_ext, name );
        std::wcscat( name_with_ext, oxorany( L".log" ) );

        piddb_cache_entry_t local_entry{};
        local_entry.m_driver_name.m_length = static_cast< std::uint16_t >( wcslen( name_with_ext ) * 2 );
        local_entry.m_driver_name.m_maximum_length = local_entry.m_driver_name.m_length + 2;
        local_entry.m_driver_name.m_buffer = name_with_ext;
        local_entry.m_timestamp = timestamp;
        return reinterpret_cast< piddb_cache_entry_t* >( kernel::rtl_lookup_element_generic_table_avl( table, &local_entry ) );
    }

    bool clear_piddb_cache_table( const wchar_t* driver_name, std::uint32_t timestamp ) {
        auto lock_addr = g_pdb->get_symbol_address( oxorany( "PiDDBLock" ) );
        auto table_addr = g_pdb->get_symbol_address( oxorany( "PiDDBCacheTable" ) );
        if ( !lock_addr || !table_addr ) {
            logging::print( oxorany( "failed to get piddb symbols" ) );
            return false;
        }

        auto lock = reinterpret_cast< void* >( lock_addr );
        auto table = reinterpret_cast< avl_table_t* >( table_addr );

        if ( !kernel::ex_acquire_resource_exclusive_lite( lock, true ) ) {
            logging::print( oxorany( "failed to acquire piddb lock" ) );
            return false;
        }

        auto entry = lookup_piddb_entry( table, timestamp, driver_name );
        if ( !entry ) {
            logging::print( oxorany( "failed to find piddb entry" ) );
            kernel::ex_release_resource_lite( lock );
            return false;
        }

        auto list_base = reinterpret_cast< std::uint64_t >( entry ) + offsetof( piddb_cache_entry_t, m_list );
        auto prev = memory::read< list_entry_t* >( list_base + offsetof( list_entry_t, m_blink ) );
        auto next = memory::read< list_entry_t* >( list_base + offsetof( list_entry_t, m_flink ) );

        if ( prev )
            memory::write< list_entry_t* >( reinterpret_cast< std::uint64_t >( prev ) + offsetof( list_entry_t, m_flink ), next );
        if ( next )
            memory::write< list_entry_t* >( reinterpret_cast< std::uint64_t >( next ) + offsetof( list_entry_t, m_blink ), prev );

        kernel::rtl_delete_element_generic_table_avl( table, entry );

        auto delete_count = memory::read< std::uint32_t >( reinterpret_cast< std::uint64_t >( table ) + offsetof( avl_table_t, m_delete_count ) );
        if ( delete_count > 0 )
            memory::write< std::uint32_t >( reinterpret_cast< std::uint64_t >( table ) + offsetof( avl_table_t, m_delete_count ), delete_count - 1 );

        kernel::ex_release_resource_lite( lock );
        logging::print( oxorany( "piddb cache table cleared" ) );
        return true;
    }

    bool clear_mm_unloaded_drivers( const wchar_t* driver_name ) {
        auto mm_unloaded_drivers = g_pdb->get_symbol_address( oxorany( "MmUnloadedDrivers" ) );
        if ( !mm_unloaded_drivers ) {
            logging::print( oxorany( "failed to get unloaded driver symbols" ) );
            return false;
        }

        auto unloaded_drivers = memory::read< std::uint64_t >( mm_unloaded_drivers );
        if ( !unloaded_drivers ) {
            logging::print( oxorany( "no entries found in unloaded drivers" ) );
            return false;
        }

        for ( auto idx = 0u; idx < 50u; ++idx ) {
            const auto unloaded_driver_addr = unloaded_drivers + idx * 0x28u;
            auto unloaded_driver = memory::read< unicode_string_t >( unloaded_driver_addr );
            if ( !unloaded_driver.m_length || !unloaded_driver.m_buffer )
                continue;

            auto name_buf = std::make_unique< wchar_t[ ] >( unloaded_driver.m_length / 2 + 1 );
            if ( !memory::read_virtual( reinterpret_cast< std::uint64_t >( unloaded_driver.m_buffer ), name_buf.get( ), unloaded_driver.m_length ) )
                continue;

            if ( std::wstring( name_buf.get( ) ).find( driver_name ) == std::wstring::npos )
                continue;

            std::array< std::uint8_t, 0x28u > zeroes{};
            memory::write_virtual( unloaded_driver_addr, zeroes.data( ), 0x28u );
            return true;
        }

        return false;
    }

    bool clear_kernel_hash_bucket_list( const wchar_t* driver_name, const wchar_t* driver_path ) {
        auto ci_pdb = std::make_unique< pdb::c_pdb >( "ci.dll" );
        if ( !ci_pdb || !ci_pdb->load( ) ) {
            logging::print( oxorany( "failed to load ci pdb" ) );
            return false;
        }

        auto lock_addr = ci_pdb->get_symbol_address( oxorany( "g_HashCacheLock" ) );
        auto list_addr = ci_pdb->get_symbol_address( oxorany( "g_KernelHashBucketList" ) );
        if ( !lock_addr || !list_addr ) {
            logging::print( oxorany( "failed to get ci symbols: lock=%llx list=%llx" ), lock_addr, list_addr );
            return false;
        }

        auto lock = reinterpret_cast< void* >( lock_addr );

        if ( !kernel::ex_acquire_resource_exclusive_lite( lock, true ) ) {
            logging::print( oxorany( "failed to acquire ci lock" ) );
            return false;
        }

        auto prev_ptr = list_addr;
        auto entry = memory::read< hash_bucket_entry_t* >( prev_ptr );

        if ( !entry ) {
            logging::print( oxorany( "hash bucket list is empty" ) );
            kernel::ex_release_resource_lite( lock );
            return true;
        }

        while ( entry ) {
            auto module_name = memory::read< unicode_string_t >(
                reinterpret_cast< std::uint64_t >( entry ) + offsetof( hash_bucket_entry_t, m_driver_name ) );

            if ( module_name.m_length == 0 ) {
                prev_ptr = reinterpret_cast< std::uint64_t >( entry );
                entry = memory::read< hash_bucket_entry_t* >( entry );
                continue;
            }

            auto name_ptr = memory::read< wchar_t* >(
                reinterpret_cast< std::uint64_t >( entry ) +
                offsetof( hash_bucket_entry_t, m_driver_name ) +
                offsetof( unicode_string_t, m_buffer ) );

            if ( !name_ptr ) {
                prev_ptr = reinterpret_cast< std::uint64_t >( entry );
                entry = memory::read< hash_bucket_entry_t* >( entry );
                continue;
            }

            auto name_buffer = std::make_unique< wchar_t[ ] >( module_name.m_length / 2 + 1 );
            if ( !memory::read_virtual( reinterpret_cast< std::uint64_t >( name_ptr ), name_buffer.get( ), module_name.m_length ) ) {
                prev_ptr = reinterpret_cast< std::uint64_t >( entry );
                entry = memory::read< hash_bucket_entry_t* >( entry );
                continue;
            }

            if ( std::wstring( name_buffer.get( ) ).find( driver_name ) != std::wstring::npos ) {
                auto next = memory::read< hash_bucket_entry_t* >( entry );
                memory::write< hash_bucket_entry_t* >( prev_ptr, next );
                kernel::free_pool( reinterpret_cast< std::uint64_t >( entry ) );
                kernel::ex_release_resource_lite( lock );
                logging::print( oxorany( "kernel hash bucket cleared" ) );
                return true;
            }

            prev_ptr = reinterpret_cast< std::uint64_t >( entry );
            entry = memory::read< hash_bucket_entry_t* >( entry );
        }

        logging::print( oxorany( "hash bucket entry not found" ) );
        kernel::ex_release_resource_lite( lock );
        return false;
    }

    bool clear_wd_filter_driver_list( ) {
        auto wd_pdb = std::make_unique< pdb::c_pdb >( "WdFilter.sys" );
        if ( !wd_pdb ) {
            logging::print( oxorany( "failed to create wd pdb" ) );
            return true;
        }

        if ( wd_pdb->load( ) ) {
            logging::print( oxorany( "filter driver found!" ) );
            logging::print( oxorany( "please disable anti-virus and restart your computer." ) );
            return false;
        }

        logging::print( oxorany( "filter driver not found" ) );
        return true;
    }
}
