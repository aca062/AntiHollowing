/*#include <windows.h>
#include <DbgHelp.h>

#pragma comment(lib, "kernel32.lib")

#include <libloaderapi.h>

void UnmappingNotif(DEBUG_EVENT* DebugEvent)
{
	switch (DebugEvent->dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
		if (DebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT &&
			DebugEvent->u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "ZwUnmapViewOfSection"))
		{
			// The process has unmapped a memory section, perform any necessary cleanup here
			// For example, you can check if the process being unmapped is the one you're interested in
			// and then perform any necessary actions or raise an alert
		}
		break;
	}
}*/