#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <windef.h>
#pragma comment (lib, "ntoskrnl.lib")

constexpr auto CREATE_SUSPENDED = 0x00000004;

typedef NTSTATUS(WINAPI* ZWQUERYINFORMATIONPROCESS)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

//DRIVER_DISPATCH HandleCustomIOCTL;
//#define IOCTL_SPOTLESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2049, METHOD_BUFFERED, FILE_ANY_ACCESS)
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\AntiHollowing");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\AntiHollowingLink");

void sCreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	//PROCESS_BASIC_INFORMATION ProcessInfo;
	//ULONG ReturnLength;
	//NTSTATUS Status;

	UNICODE_STRING FunctionName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

	PVOID FunctionAddress = MmGetSystemRoutineAddress(&FunctionName);

	if (FunctionAddress == NULL)
	{
		// failed to obtain the address of ZwQueryInformationProcess
		DbgPrint("ZwQueryInformationProcess no conseguida");
	}
	else {
		// succeed to obtain the address of ZwQueryInformationProcess

	}

	if (create)
	{
		PEPROCESS process = NULL;
		PUNICODE_STRING parentProcessName = NULL, processName = NULL;
		//ULONG ProcessFlags;

		PsLookupProcessByProcessId(ppid, &process);
		SeLocateProcessImageName(process, &parentProcessName);

		PsLookupProcessByProcessId(pid, &process);
		SeLocateProcessImageName(process, &processName);

		//ProcessFlags = process->Flags;

		DbgPrint("%d %wZ\n\t\t%d %wZ", ppid, parentProcessName, pid, processName);
	}
	else
	{

		//DbgPrint("Process %d lost child %d", ppid, pid);
	}
}

/*void UnmappingNotif(
	DEBUG_EVENT* DebugEvent
)
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

/*LONG WINAPI UnmappingNotif(EXCEPTION_POINTERS* ExceptionInfo)
{
	DWORD processId = GetCurrentProcessId();

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
		ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 0 &&
		ExceptionInfo->ExceptionRecord->ExceptionInformation[1] == 1)
	{
		// The process has unmapped a memory section, perform any necessary cleanup here
		// For example, you can check if the process being unmapped is the one you're interested in
		// and then perform any necessary actions or raise an alert

		// Return EXCEPTION_EXECUTE_HANDLER to suppress the default exception handling

		DbgPrint(("Proceso desasignando memoria: %d"), processId);

		return EXCEPTION_EXECUTE_HANDLER;
	}

	// Return EXCEPTION_CONTINUE_SEARCH to allow the default exception handling to proceed
	return EXCEPTION_CONTINUE_SEARCH;
}*/

void sCreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(pid);

	/*CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(pid, &ctx))
	{
		if (ctx.EFlags & 0x00010000)
		{
			// The process is not suspended
		}
		else
		{
			// The process is suspended
		}
	}*/



	if (createInfo != NULL)
	{
		if (createInfo->Flags & CREATE_SUSPENDED)
		{
		//	DbgPrint("[!] Access to launch notepad.exe was denied!");
		//	createInfo->CreationStatus = STATUS_ACCESS_DENIED;
			DbgPrint(("Proceso suspendido: %llu"), createInfo->Flags);
		}
		else 
		{
			DbgPrint(("Proceso no suspendido: %llu"), createInfo->Flags);

		}

	}
}

void sLoadImageNotifyRoutine(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
	UNREFERENCED_PARAMETER(imageInfo);
	PEPROCESS process = NULL;
	PUNICODE_STRING processName = NULL;
	PsLookupProcessByProcessId(pid, &process);
	SeLocateProcessImageName(process, &processName);

	DbgPrint("%wZ (%d) loaded %wZ", processName, pid, imageName);
}

void sCreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create)
{
	if (create)
	{
		DbgPrint("%d created thread %d", pid, tid);
	}
	else
	{
		DbgPrint("Thread %d of process %d exited", tid, pid);
	}
}

void DriverUnload(PDRIVER_OBJECT dob)
{
	DbgPrint("Driver unloaded, deleting symbolic links and devices");
	IoDeleteDevice(dob->DeviceObject);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
	PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, TRUE);
	//PsRemoveLoadImageNotifyRoutine(sLoadImageNotifyRoutine);
	//PsRemoveCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);
	//PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);
}

/*NTSTATUS HandleCustomIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	CHAR* messageFromKernel = "ohai from them kernelz";

	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_SPOTLESS)
	{
		DbgPrint("IOCTL_SPOTLESS (0x%x) issued", stackLocation->Parameters.DeviceIoControl.IoControlCode);
		DbgPrint("Input received from userland: %s", (char*)Irp->AssociatedIrp.SystemBuffer);
	}

	Irp->IoStatus.Information = strlen(messageFromKernel);
	Irp->IoStatus.Status = STATUS_SUCCESS;

	DbgPrint("Sending to userland: %s", messageFromKernel);
	RtlCopyMemory((char*)Irp->AssociatedIrp.SystemBuffer, messageFromKernel, strlen((char*)Irp->AssociatedIrp.SystemBuffer));

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}*/

/*NTSTATUS MajorFunctions(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (stackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrint("Handle to symbolink link %wZ opened", DEVICE_SYMBOLIC_NAME);
		break;
	case IRP_MJ_CLOSE:
		DbgPrint("Handle to symbolink link %wZ closed", DEVICE_SYMBOLIC_NAME);
		break;
	default:
		break;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}*/

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;

	// routine that will execute when our driver is unloaded/service is stopped
	DriverObject->DriverUnload = DriverUnload;
	//SetUnhandledExceptionFilter(UnmappingNotif);

	// routine for handling IO requests from userland
	//DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleCustomIOCTL;

	// routines that will execute once a handle to our device's symbolik link is opened/closed
	//DriverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctions;
	//DriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctions;

	DbgPrint("Driver loaded");

	// subscribe to notifications
	PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, FALSE);
	//PsSetLoadImageNotifyRoutine(sLoadImageNotifyRoutine);
	//PsSetCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);
	//PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE);
	DbgPrint("Listeners installed..");

	IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create device %wZ", DEVICE_NAME);
	}
	else
	{
		DbgPrint("Device %wZ created", DEVICE_NAME);
	}

	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
	if (NT_SUCCESS(status))
	{
		DbgPrint("Symbolic link %wZ created", DEVICE_SYMBOLIC_NAME);
	}
	else
	{
		DbgPrint("Error creating symbolic link %wZ", DEVICE_SYMBOLIC_NAME);
	}

	return STATUS_SUCCESS;
}