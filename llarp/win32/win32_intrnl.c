// there's probably an use case for a _newer_ implementation
// of pthread_setname_np(3), in fact, I may just merge _this_
// upstream...
#ifdef _MSC_VER
#include <windows.h>

typedef HRESULT(FAR PASCAL* p_SetThreadDescription)(void*, const wchar_t*);
#define EXCEPTION_SET_THREAD_NAME ((DWORD)0x406D1388)

typedef struct _THREADNAME_INFO
{
    DWORD dwType;     /* must be 0x1000 */
    LPCSTR szName;    /* pointer to name (in user addr space) */
    DWORD dwThreadID; /* thread ID (-1=caller thread) */
    DWORD dwFlags;    /* reserved for future use, must be zero */
} THREADNAME_INFO;

void SetThreadName(DWORD dwThreadID, LPCSTR szThreadName)
{
    THREADNAME_INFO info;
    DWORD infosize;
    HANDLE hThread;
    /* because loonix is SHIT and limits thread names to 16 bytes */
    wchar_t thr_name_w[16];
    p_SetThreadDescription _SetThreadDescription;

    /* current win10 flights now have a new named-thread API, let's try to use
     * that first! */
    /* first, dlsym(2) the new call from system library */
    hThread = NULL;
    _SetThreadDescription = (p_SetThreadDescription)GetProcAddress(GetModuleHandle("kernel32"), "SetThreadDescription");
    if (_SetThreadDescription)
    {
        /* grab another reference to the thread */
        hThread = OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, dwThreadID);
        /* windows takes unicode, our input is utf-8 or plain ascii */
        MultiByteToWideChar(CP_ACP, 0, szThreadName, -1, thr_name_w, 16);
        if (hThread)
            _SetThreadDescription(hThread, thr_name_w);
        else
            goto old; /* for whatever reason, we couldn't get a handle to the thread.
                         Just use the old method. */
    }
    else
    {
    old:
        info.dwType = 0x1000;
        info.szName = szThreadName;
        info.dwThreadID = dwThreadID;
        info.dwFlags = 0;

        infosize = sizeof(info) / sizeof(DWORD);

        __try
        {
            RaiseException(EXCEPTION_SET_THREAD_NAME, 0, infosize, (DWORD*)&info);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {}
    }
    /* clean up */
    if (hThread)
        CloseHandle(hThread);
}
#endif

#ifdef _WIN32
#if 0
// Generate a core dump if we crash. Finally.
// Unix-style, we just leave a file named "core" in
// the user's working directory. Gets overwritten if
// a new crash occurs.
#include <dbghelp.h>
#ifdef _MSC_VER
#pragma comment(lib, "dbghelp.lib")
#endif

HRESULT
GenerateCrashDump(MINIDUMP_TYPE flags, EXCEPTION_POINTERS *seh)
{
  HRESULT error                         = S_OK;
  MINIDUMP_USER_STREAM_INFORMATION info = {0};
  MINIDUMP_USER_STREAM stream           = {0};

  // get the time
  SYSTEMTIME sysTime = {0};
  GetSystemTime(&sysTime);

  // get the computer name
  char compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
  DWORD compNameLen                          = ARRAYSIZE(compName);
  GetComputerNameA(compName, &compNameLen);

  // This information is written to a core dump user stream
  char extra_info[1024] = {0};
  snprintf(extra_info, 1024,
           "hostname=%s;datetime=%02u-%02u-%02u_%02u-%02u-%02u", compName,
           sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour,
           sysTime.wMinute, sysTime.wSecond);

  // open the file
  HANDLE hFile =
      CreateFileA("core", GENERIC_READ | GENERIC_WRITE,
                  FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if(hFile == INVALID_HANDLE_VALUE)
  {
    error = GetLastError();
    error = HRESULT_FROM_WIN32(error);
    return error;
  }

  // get the process information
  HANDLE hProc = GetCurrentProcess();
  DWORD procID = GetCurrentProcessId();

  // if we have SEH info, package it up
  MINIDUMP_EXCEPTION_INFORMATION sehInfo = {0};
  MINIDUMP_EXCEPTION_INFORMATION *sehPtr = NULL;

  // Collect hostname and time
  info.UserStreamCount = 1;
  info.UserStreamArray = &stream;
  stream.Type          = CommentStreamA;
  stream.BufferSize    = strlen(extra_info) + 1;
  stream.Buffer        = extra_info;

  if(seh)
  {
    sehInfo.ThreadId          = GetCurrentThreadId();
    sehInfo.ExceptionPointers = seh;
    sehInfo.ClientPointers    = FALSE;
    sehPtr                    = &sehInfo;
  }

  // generate the crash dump
  BOOL result =
      MiniDumpWriteDump(hProc, procID, hFile, flags, sehPtr, &info, NULL);
  if(!result)
  {
    error = (HRESULT)GetLastError();  // already an HRESULT
  }

  // close the file
  CloseHandle(hFile);
  return error;
}

// ok try a UNIX-style signal handler
LONG FAR PASCAL win32_signal_handler(EXCEPTION_POINTERS *e)
{
  MessageBox(NULL,
             "A fatal error has occurred. A core dump was generated and "
             "dropped in the daemon's working directory. Please create an "
             "issue at https://github.com/loki-network/loki-project, and "
             "attach the core dump for further assistance.",
             "Fatal Error", MB_ICONHAND);
  GenerateCrashDump(
      MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithThreadInfo
          | MiniDumpWithProcessThreadData | MiniDumpWithFullMemoryInfo
          | MiniDumpWithUnloadedModules | MiniDumpWithFullAuxiliaryState
          | MiniDumpIgnoreInaccessibleMemory | MiniDumpWithTokenInformation,
      e);
  exit(127);
  return 0;
}
#endif
#endif
