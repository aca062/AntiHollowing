#include <Ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#define IOCTL_SPOTLESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2049, METHOD_BUFFERED, FILE_ANY_ACCESS)
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\SpotlessDevice");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\SpotlessDeviceLink");

void sCreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	if (create)
	{
		PEPROCESS process = NULL;
		PUNICODE_STRING parentProcessName = NULL, processName = NULL;

		PsLookupProcessByProcessId(ppid, &process);
		SeLocateProcessImageName(process, &parentProcessName);

		PsLookupProcessByProcessId(pid, &process);
		SeLocateProcessImageName(process, &processName);

		DbgPrint("%d %wZ\n\t\t%d %wZ", ppid, parentProcessName, pid, processName);
	}
	else
	{
		DbgPrint("Process %d lost child %d", ppid, pid);
	}
}

void sCreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(pid);

	if (createInfo != NULL)
	{
		if (wcsstr(createInfo->CommandLine->Buffer, L"notepad") != NULL)
		{
			DbgPrint("[!] Access to launch notepad.exe was denied!");
			createInfo->CreationStatus = STATUS_ACCESS_DENIED;
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
	PsRemoveLoadImageNotifyRoutine(sLoadImageNotifyRoutine);
	PsRemoveCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);
}

NTSTATUS MajorFunctions(PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;

	// routine that will execute when our driver is unloaded/service is stopped
	DriverObject->DriverUnload = DriverUnload;

	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctions;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctions;

	DbgPrint("Driver loaded");

	// subscribe to notifications
	PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, FALSE);
	PsSetLoadImageNotifyRoutine(sLoadImageNotifyRoutine);
	PsSetCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE);
	DbgPrint("Listeners isntalled..");

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