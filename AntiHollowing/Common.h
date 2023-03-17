#include <windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "kernel32.lib")

void UnmappingNotif(DEBUG_EVENT* DebugEvent);