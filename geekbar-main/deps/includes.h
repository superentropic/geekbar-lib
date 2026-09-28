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
#include <array>
#include <functional>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <numbers>
#include <unordered_set>
#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
namespace ch = std::chrono;

#include <ext/oxorany/oxorany.h>
#include <core/utility/utility.hxx>
#include <core/geekbar/geekbar.hxx>