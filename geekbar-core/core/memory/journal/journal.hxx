#pragma once

namespace usn {
    static constexpr std::uint32_t buf_size = 65536;
    static constexpr std::uint32_t journal_size = 0x800000;
    static constexpr std::uint32_t journal_delta = 0x100000;

    static const std::unordered_map<std::uint32_t , std::string> m_reason_map = {
        { USN_REASON_DATA_OVERWRITE,        "DATA_OVERWRITE"        },
        { USN_REASON_DATA_EXTEND,           "DATA_EXTEND"           },
        { USN_REASON_DATA_TRUNCATION,       "DATA_TRUNCATION"       },
        { USN_REASON_NAMED_DATA_OVERWRITE,  "NAMED_DATA_OVERWRITE"  },
        { USN_REASON_NAMED_DATA_EXTEND,     "NAMED_DATA_EXTEND"     },
        { USN_REASON_NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION" },
        { USN_REASON_FILE_CREATE,           "FILE_CREATE"           },
        { USN_REASON_FILE_DELETE,           "FILE_DELETE"           },
        { USN_REASON_EA_CHANGE,             "EA_CHANGE"             },
        { USN_REASON_SECURITY_CHANGE,       "SECURITY_CHANGE"       },
        { USN_REASON_RENAME_OLD_NAME,       "RENAME_OLD_NAME"       },
        { USN_REASON_RENAME_NEW_NAME,       "RENAME_NEW_NAME"       },
        { USN_REASON_INDEXABLE_CHANGE,      "INDEXABLE_CHANGE"      },
        { USN_REASON_BASIC_INFO_CHANGE,     "BASIC_INFO_CHANGE"     },
        { USN_REASON_HARD_LINK_CHANGE,      "HARD_LINK_CHANGE"      },
        { USN_REASON_COMPRESSION_CHANGE,    "COMPRESSION_CHANGE"    },
        { USN_REASON_ENCRYPTION_CHANGE,     "ENCRYPTION_CHANGE"     },
        { USN_REASON_OBJECT_ID_CHANGE,      "OBJECT_ID_CHANGE"      },
        { USN_REASON_REPARSE_POINT_CHANGE,  "REPARSE_POINT_CHANGE"  },
        { USN_REASON_STREAM_CHANGE,         "STREAM_CHANGE"         },
        { USN_REASON_CLOSE,                 "CLOSE"                 },
    };

    std::string format_reasons ( DWORD reasons ) {
        std::string result;
        for ( const auto& [flag , name] : m_reason_map ) {
            if ( reasons & flag ) {
                if ( !result.empty ( ) ) result += oxorany ( " | " );
                result += name;
            }
        }
        return result.empty ( ) ? oxorany ( "UNKNOWN" ) : result;
    }

    class c_journal {
    public:
        bool clear ( ) {
            return clear_drive ( "C:" );
        }

    private:
        bool clear_drive ( const std::string& drive ) {
            const auto path = std::format ( "\\\\.\\{}" , drive );
            const auto vol = CreateFileA (
                path.c_str ( ) ,
                GENERIC_READ | GENERIC_WRITE ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE ,
                nullptr , OPEN_EXISTING , 0 , nullptr
            );

            if ( vol == INVALID_HANDLE_VALUE ) {
                logging::print ( oxorany ( "failed to open %s (error: %lu)" ) , drive.c_str ( ) , GetLastError ( ) );
                return false;
            }

            const auto result = delete_journal ( vol , drive );
            CloseHandle ( vol );
            return result;
        }

        bool delete_journal ( HANDLE vol , const std::string& drive ) {
            DWORD br {};
            USN_JOURNAL_DATA_V0 jd {};
            if ( !DeviceIoControl ( vol , FSCTL_QUERY_USN_JOURNAL ,
                nullptr , 0 , &jd , sizeof ( jd ) , &br , nullptr ) ) {
                logging::print ( oxorany ( "failed to get %s journal (error: %lu)" ) , drive.c_str ( ) , GetLastError ( ) );
                return false;
            }

            DELETE_USN_JOURNAL_DATA del {};
            del.UsnJournalID = jd.UsnJournalID;
            del.DeleteFlags = USN_DELETE_FLAG_DELETE;

            if ( !DeviceIoControl ( vol , FSCTL_DELETE_USN_JOURNAL ,
                &del , sizeof ( del ) , nullptr , 0 , &br , nullptr ) ) {
                logging::print ( oxorany ( "failed to delete %s journal (error: %lu)" ) , drive.c_str ( ) , GetLastError ( ) );
                return false;
            }

            return true;
        }
    };
}