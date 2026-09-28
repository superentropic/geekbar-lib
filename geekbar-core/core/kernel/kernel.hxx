#pragma once

namespace kernel {
    bool ex_acquire_resource_exclusive_lite( void* resource, bool wait = true ) {
        static auto addr = g_pdb->get_symbol_address( oxorany( "ExAcquireResourceExclusiveLite" ) );
        if ( !addr ) return false;
        return g_syscall->call_kernel< std::uint64_t >( addr,
            reinterpret_cast< std::uint64_t >( resource ),
            wait ? 1u : 0u ) != 0;
    }

    bool ex_release_resource_lite( void* resource ) {
        static auto addr = g_pdb->get_symbol_address( oxorany( "ExReleaseResourceLite" ) );
        if ( !addr || !resource ) return false;
        g_syscall->call_kernel( addr, reinterpret_cast< std::uint64_t >( resource ) );
        return true;
    }

    void* rtl_lookup_element_generic_table_avl( void* table, void* buffer ) {
        static auto addr = g_pdb->get_symbol_address( "RtlLookupElementGenericTableAvl" );
        if ( !addr )
            return nullptr;
        auto result = g_syscall->call_kernel< std::uint64_t >( addr,
            reinterpret_cast< std::uint64_t >( table ),
            reinterpret_cast< std::uint64_t >( buffer ) );
        if ( !result )
            return nullptr;
        return reinterpret_cast< void* >( result );
    }

    bool rtl_delete_element_generic_table_avl( void* table, void* buffer ) {
        static auto addr = g_pdb->get_symbol_address( "RtlDeleteElementGenericTableAvl" );
        if ( !addr )
            return false;
        auto result = g_syscall->call_kernel< std::uint64_t >( addr,
            reinterpret_cast< std::uint64_t >( table ),
            reinterpret_cast< std::uint64_t >( buffer ) );
        return result != 0;
    }

    std::uint64_t allocate_pool( std::uint64_t pool_type, std::uint64_t size ) {
        static auto addr = g_pdb->get_symbol_address( "ExAllocatePoolWithTag" );
        if ( !addr )
            return 0;
        return g_syscall->call_kernel< std::uint64_t >( addr, pool_type, size, 'BwtE' );
    }

    bool free_pool( std::uint64_t address ) {
        if ( !address )
            return false;
        static auto addr = g_pdb->get_symbol_address( "ExFreePool" );
        if ( !addr )
            return false;
        g_syscall->call_kernel( addr, address );
        return true;
    }

    void* mm_allocate_independent_pages( std::size_t size ) {
        static auto addr = g_pdb->get_symbol_address( "MmAllocateIndependentPages" );
        if ( !addr )
            return nullptr;

        return g_syscall->call_kernel<void*>( addr, size, -1 );
    }

    void memset( void* dst, int value, std::uint64_t size ) {
        static auto addr = g_pdb->get_symbol_address( "memset" );
        if ( !addr )
            return;

        g_syscall->call_kernel( addr, dst, value, size );
    }

    bool mm_free_independent_pages( std::uint64_t address, std::uint32_t size ) {
        static auto addr = g_pdb->get_symbol_address( "MmFreeIndependentPages" );
        if ( !addr )
            return false;
        g_syscall->call_kernel( addr, address, size );
        return true;
    }

    bool mm_set_page_protection( std::uint64_t address, std::uint32_t size, std::uint32_t new_protect ) {
        static auto addr = g_pdb->get_symbol_address( "MmSetPageProtection" );
        if ( !addr )
            return false;
        auto result = g_syscall->call_kernel< std::uint64_t >( addr, address, size, new_protect );
        return result != 0;
    }

    std::uint64_t mm_allocate_contiguous_memory( std::uint64_t size ) {
        static auto addr = g_pdb->get_symbol_address( "MmAllocateContiguousMemory" );
        if ( !addr )
            return 0;
        return g_syscall->call_kernel< std::uint64_t >( addr, size, 0xFFFFFFFFFFFFFFFFull );
    }

    bool mm_free_contiguous_memory( std::uint64_t address ) {
        static auto addr = g_pdb->get_symbol_address( "MmFreeContiguousMemory" );
        if ( !addr )
            return false;
        g_syscall->call_kernel( addr, address );
        return true;
    }

    std::uint64_t mm_get_physical_address( std::uint64_t virtual_address ) {
        static auto addr = g_pdb->get_symbol_address( "MmGetPhysicalAddress" );
        if ( !addr )
            return 0;
        return g_syscall->call_kernel< std::uint64_t >( addr, virtual_address );
    }

    std::uint64_t mi_reserve_system_pte( std::uint32_t count ) {
        static auto addr = g_pdb->get_symbol_address( "MiReserveSystemPtes" );
        if ( !addr )
            return 0;
        return g_syscall->call_kernel< std::uint64_t >( addr, count );
    }

    void mi_release_system_pte( std::uint64_t address ) {
        static auto addr = g_pdb->get_symbol_address( "MiReleaseSystemPtes" );
        if ( !addr )
            return;
        g_syscall->call_kernel( addr, address, 1 );
    }

    std::uint64_t mi_initialize_pfn( std::uint64_t page_va, std::uint64_t pte_va, std::uint64_t pfn_number ) {
        static auto addr = g_pdb->get_symbol_address( "MiInitializePfn" );
        if ( !addr )
            return 0;
        g_syscall->call_kernel( addr, page_va, pte_va, pfn_number );
        return pfn_number;
    }

    void invalidate_tlb_entry( std::uint64_t virtual_address ) {
        static auto addr = g_pdb->get_symbol_address( "KeFlushSingleTb" );
        if ( !addr ) {
            return;
        }
        g_syscall->call_kernel( addr, virtual_address, 1 );
    }

    void flush_tlb_all( ) {
        static auto addr = g_pdb->get_symbol_address( "KeFlushEntireTb" );
        if ( !addr ) {
            auto cr4 = __readcr4( );
            __writecr4( cr4 );
            __writecr3( __readcr3( ) );
            return;
        }
        g_syscall->call_kernel( addr, 0, 0 );
    }

    std::uint64_t ex_allocate_pool( std::uint64_t pool_type, std::uint64_t size, std::uint32_t tag = 'PgeM' ) {
        static auto addr = g_pdb->get_symbol_address( "ExAllocatePoolWithTag" );
        if ( !addr )
            return 0;
        return g_syscall->call_kernel< std::uint64_t >( addr, pool_type, size, tag );
    }

    void ex_free_pool( std::uint64_t address ) {
        if ( !address )
            return;
        static auto addr = g_pdb->get_symbol_address( "ExFreePool" );
        if ( !addr )
            return;
        g_syscall->call_kernel( addr, address );
    }

    void* ps_lookup_process_by_pid( std::uint32_t process_id ) {
        static auto addr = g_pdb->get_symbol_address( "PsLookupProcessByProcessId" );
        if ( !addr )
            return nullptr;

        void* process = nullptr;
        auto result = g_syscall->call_kernel<NTSTATUS>(
            addr,
            reinterpret_cast< HANDLE >( process_id ),
            &process
        );

        if ( result ) {
            logging::print( oxorany( "failed to find process (%d)" ), result );
            return nullptr;
        }

        return process;
    }

    bool mark_pages_bad( std::uint64_t pa, std::uint64_t size ) {
        static auto addr = g_pdb->get_symbol_address( "MmMarkPhysicalMemoryAsBad" );
        if ( !addr ) {
            logging::print( oxorany( "failed to find MmMarkPhysicalMemoryAsBad" ) );
            return false;
        }

        std::uint64_t base = pa;
        std::uint64_t bytes = size;

        auto result = g_syscall->call_kernel<std::int32_t>(
            addr,
            &base,
            &bytes
        );

        if ( result < 0 ) {
            logging::print( oxorany( "MmMarkPhysicalMemoryAsBad failed: 0x%x (pa: 0x%llx)" ), result, pa );
            return false;
        }

        return true;
    }

    template < typename type_t = std::uint64_t >
    std::optional < type_t > allocate_pages( std::size_t size ) {
        auto base_address = mm_allocate_independent_pages( size );
        if ( !base_address )
            return std::nullopt;

        kernel::memset( base_address, 0, size );

        const auto pa = kernel::mm_get_physical_address(
            reinterpret_cast< std::uint64_t >( base_address ) );

        // This memory is immediately used as a page-table page by the mapping
        // code.  Marking it as bad after allocating it corrupts the memory
        // manager's view of a live page and can destabilize the whole system.

        return std::optional < type_t >( reinterpret_cast < type_t >( base_address ) );
    }
} // namespace kernel
