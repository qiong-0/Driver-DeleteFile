#include <ntddk.h>

#define DEVICE_NAME	L"\\Device\\del"
#define SYM_NAME	L"\\DosDevices\\del"

#define IOCTL_DeleteFile	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _Data
{
	ULONG	Pid;
	PVOID	Address;
	ULONG	Size;
	PVOID   Buffer;
} Data, * PData;

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLinkName = { 0 };
	RtlInitUnicodeString(&symLinkName, SYM_NAME);
	IoDeleteSymbolicLink(&symLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

HANDLE	FD_OpenFile(UNICODE_STRING szFileName)
{
	NTSTATUS			ntStatus;
	UNICODE_STRING		FileName;
	OBJECT_ATTRIBUTES	objectAttributes;
	HANDLE				hFile;
	IO_STATUS_BLOCK		ioStatus;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return NULL;

	InitializeObjectAttributes(&objectAttributes, &szFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = IoCreateFile(&hFile, FILE_READ_ATTRIBUTES, &objectAttributes, &ioStatus,
		0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(ntStatus))
		return NULL;

	return  hFile;
}

NTSTATUS FD_SetFileCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	Irp->UserIosb->Status = Irp->IoStatus.Status;
	Irp->UserIosb->Information = Irp->IoStatus.Information;
	KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);
	IoFreeIrp(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

BOOLEAN	FD_StripFileAttributes(HANDLE FileHandle)
{
	NTSTATUS				ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT			fileObject;
	PDEVICE_OBJECT			DeviceObject;
	PIRP					Irp;
	KEVENT					SycEvent;
	FILE_BASIC_INFORMATION	FileInformation;
	IO_STATUS_BLOCK			ioStatus;
	PIO_STACK_LOCATION		irpSp;
	ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE, *IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}
	DeviceObject = IoGetRelatedDeviceObject(fileObject);
	Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
	if (Irp == NULL)
	{
		ObDereferenceObject(fileObject);
		return FALSE;
	}
	KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);
	memset(&FileInformation, 0, 0x28);
	FileInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &SycEvent;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;
	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_BASIC_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileBasicInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;
	IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);
	IoCallDriver(DeviceObject, Irp);
	KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);
	ObDereferenceObject(fileObject);
	return TRUE;
}

BOOLEAN FD_DeleteFile(HANDLE FileHandle)
{
	NTSTATUS          ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT      fileObject;
	PDEVICE_OBJECT    DeviceObject;
	PIRP              Irp;
	KEVENT            SycEvent;
	FILE_DISPOSITION_INFORMATION    FileInformation;
	IO_STATUS_BLOCK					ioStatus;
	PIO_STACK_LOCATION				irpSp;
	PSECTION_OBJECT_POINTERS		pSectionObjectPointer;
	ntStatus = ObReferenceObjectByHandle(FileHandle, DELETE, *IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}
	DeviceObject = IoGetRelatedDeviceObject(fileObject);
	Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
	if (Irp == NULL)
	{
		ObDereferenceObject(fileObject);
		return FALSE;
	}
	KeInitializeEvent(&SycEvent, SynchronizationEvent, FALSE);
	FileInformation.DeleteFile = TRUE;
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &SycEvent;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;
	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;
	IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);
	pSectionObjectPointer = fileObject->SectionObjectPointer;
	pSectionObjectPointer->ImageSectionObject = 0;
	pSectionObjectPointer->DataSectionObject = 0;
	IoCallDriver(DeviceObject, Irp);
	KeWaitForSingleObject(&SycEvent, Executive, KernelMode, TRUE, NULL);
	ObDereferenceObject(fileObject);
	return TRUE;
}

BOOLEAN	ForceDeleteFile(UNICODE_STRING szFileName)
{
	HANDLE		hFile = NULL;
	BOOLEAN		status = FALSE;
	__try
	{
		if ((hFile = FD_OpenFile(szFileName)) == NULL)
		{
			return FALSE;
		}
		if (FD_StripFileAttributes(hFile) == FALSE)
		{
			ZwClose(hFile);
			return FALSE;
		}
		status = FD_DeleteFile(hFile);
		ZwClose(hFile);
		return status;
	}
	__except (1)
	{

	}
	return FALSE;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID InputData = NULL, OutputData = NULL;
	ULONG InputDataConsumed = 0, OutputDataLength = 0;
	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(pIrp);
	InputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputDataLength = io->Parameters.DeviceIoControl.OutputBufferLength;
	KIRQL irql;
	switch (io->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DeleteFile:
	{
		ANSI_STRING AnsiBuffer = { 0 };
		UNICODE_STRING DeleteFilePath = { 0 };
		AnsiBuffer.Buffer = ((PData)InputData)->Buffer;
		AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(((PData)InputData)->Buffer);
		RtlAnsiStringToUnicodeString(&DeleteFilePath, &AnsiBuffer, TRUE);
		ForceDeleteFile(DeleteFilePath);
		RtlFreeUnicodeString(&DeleteFilePath);
		Status = STATUS_SUCCESS;
		break;
	}
	default:
		Status = STATUS_UNSUCCESSFUL;
		break;
	}
	if (Status == STATUS_SUCCESS)
	{
		pIrp->IoStatus.Information = OutputDataLength;
	}
	else
	{
		pIrp->IoStatus.Information = 0;
	}
	pIrp->IoStatus.Status = Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	UNREFERENCED_PARAMETER(pRegistryString);
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	PDEVICE_OBJECT pDevObj;
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	Status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	RtlInitUnicodeString(&ustrLinkName, SYM_NAME);
	Status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(pDevObj);
		return Status;
	}
	//DbgPrint("IOCTL_Protect=%d\n", IOCTL_DeleteFile);
	return STATUS_SUCCESS;
}