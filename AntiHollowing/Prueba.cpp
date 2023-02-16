#include <ntifs.h>

NTSTATUS BoosterCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS BoosterWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void BoosterUnload(PDRIVER_OBJECT DriverObject);
void sCreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create);

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING /*RegistryPath*/) {
	KdPrint(("Boster: DriverEntry\n"));

	DriverObject->DriverUnload = BoosterUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = BoosterCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = BoosterCreateClose;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = BoosterWrite;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Booster");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(
		DriverObject,           // our driver object
		0,                      // no need for extra bytes
		&devName,               // the device name
		FILE_DEVICE_UNKNOWN,    // device type
		0,                      // characteristics flags
		FALSE,                  // not exclusive
		&DeviceObject);         // the resulting pointer
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Booster");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);   // important!
		return status;
	}

	return STATUS_SUCCESS;
}

void BoosterUnload(_In_ PDRIVER_OBJECT DriverObject) {
	KdPrint(("Boster: Driver unload\n"));

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Booster");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
}

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

		DbgPrint("%p %wZ\n\t\t%p %wZ", ppid, parentProcessName, pid, processName);
	}
	else
	{
		DbgPrint("Process %p lost child %p", ppid, pid);
	}
}

NTSTATUS BoosterCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS BoosterWrite(PDEVICE_OBJECT, PIRP) {
	auto status = STATUS_SUCCESS;

	PsSetCreateProcessNotifyRoutine(sCreateProcessNotifyRoutine, FALSE);

	return status;
}