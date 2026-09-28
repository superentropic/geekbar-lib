#pragma once

namespace cache {
	bool clear_piddb_cache_table( const wchar_t* driver_name, std::uint32_t timestamp );
	bool clear_kernel_hash_bucket_list( const wchar_t* driver_name, const wchar_t* driver_path );
	bool clear_mm_unloaded_drivers( const wchar_t* driver_name );
	bool clear_wd_filter_driver_list( );
}

namespace service {
	class c_service {
	public:
		bool create( ) {
			if ( !load_driver_privilage( true ) ) {
				logging::print( oxorany( "failed to enable driver loading privilege.\n" ) );
				return false;
			}

			utility::gen_rnd_str( m_driver_name );
			logging::print( oxorany( "driver name: %ls" ), m_driver_name );

			std::memset( m_driver_path, 0, sizeof( m_driver_path ) );
			const wchar_t* prefix = oxorany( L"\\??\\" );
			std::wcscat( m_driver_path, prefix );
			auto file_path = m_driver_path + std::wcslen( prefix );
			GetTempPathW( MAX_PATH, file_path );
			std::wcscat( file_path, m_driver_name );
			std::wcscat( file_path, oxorany( L".log" ) );

			if ( !install_service( m_driver_name ) ) {
				load_driver_privilage( false );
				return false;
			}

			return true;
		}

		bool cleanup( ) {
			logging::print( oxorany( "cleanup stage: PiDDB cache" ) );
			if ( !cache::clear_piddb_cache_table( m_driver_name, get_timestamp( ) ) ) {
				logging::print( oxorany( "cleanup failed at PiDDB cache stage" ) );
				return false;
			}

			logging::print( oxorany( "cleanup stage: kernel hash bucket" ) );
			if ( !cache::clear_kernel_hash_bucket_list( m_driver_name, m_driver_path ) ) {
				logging::print( oxorany( "cleanup failed at kernel hash bucket stage" ) );
				return false;
			}

			logging::print( oxorany( "cleanup stage: WdFilter" ) );
			if ( !cache::clear_wd_filter_driver_list( ) ) {
				logging::print( oxorany( "cleanup failed at WdFilter stage" ) );
				return false;
			}

			memset( driver_bytes, 0, sizeof( driver_bytes ) );
			return true;
		}

		bool clean_unloaded_driver( ) {
			return cache::clear_mm_unloaded_drivers( m_driver_name );
		}

		bool unload( ) {
			uninstall_services( );
			load_driver_privilage( false );
			return true;
		}

	private:
		wchar_t m_driver_name[ 20 ]{ };
		wchar_t m_driver_path[ MAX_PATH ]{ };

		std::uint32_t get_timestamp( ) {
			auto dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( driver_bytes );
			if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
				return 0;

			auto nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS64 >( reinterpret_cast< std::uint64_t >( driver_bytes ) + dos_header->e_lfanew );
			if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
				return 0;

			return nt_headers->FileHeader.TimeDateStamp;
		}
	};
}
