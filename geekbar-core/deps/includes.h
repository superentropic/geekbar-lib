#pragma once
#include <chrono>
#include <ctime>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <winternl.h>
#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_
#include <cstdint>
#include <DbgHelp.h>
#include <thread>
#include <functional>
#include <map>
#include <atlbase.h>
#include <string>
#include <memory>
#include <random>
#include <ntstatus.h>
#if defined(__has_include)
#if __has_include(<dia2.h>) && __has_include(<diacreate.h>)
#define GEEKBAR_HAS_DIA 1
#include <dia2.h>
#include <diacreate.h>
#else
#define GEEKBAR_HAS_DIA 0
#endif
#else
#define GEEKBAR_HAS_DIA 0
#endif
#include <array>
#include <unordered_map>
#include <atomic>
#include <numbers>
#include <unordered_set>
#include <aclapi.h>
#include <shared_mutex>
#pragma comment(lib, "advapi32.lib")
#if GEEKBAR_HAS_DIA
#pragma comment(lib, "diaguids.lib")
#endif
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
namespace ch = std::chrono;

#include <deps/ia32/ia32.h>
#include <ext/oxorany/include.h>
#include <core/utility/utility.hxx>

#include <deps/pdb/pdb.hxx>
auto g_pdb = std::make_shared<pdb::c_pdb>( oxorany( "ntoskrnl.exe" ) );

#include <ext/service/driver/driver.hxx>
auto g_driver = std::make_shared<driver::c_driver>( );

#include <ext/service/bytes.h>
#include <ext/service/service.hxx>
#include <ext/service/startup.hxx>
auto g_service = std::make_shared<service::c_service>( );

#include <core/paging/paging.hxx>
auto g_paging = std::make_unique< paging::c_paging >( );

#include <core/memory/memory.hxx>
#include <core/memory/process.hxx>
#include <core/syscall/syscall.hxx>
auto g_syscall = std::make_unique< syscall::c_syscall >( );

#include <core/kernel/kernel.hxx>
#include <core/memory/mapping/mapping.hxx>
auto g_mapping = std::make_unique< mapping::c_mapping >( );

#include <core/memory/journal/journal.hxx>
auto g_usn_journal = std::make_unique< usn::c_journal >( );

#include <ext/service/cache/cache.hxx>
#include <core/utility/crash.hxx>
