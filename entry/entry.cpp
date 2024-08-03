#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntimage.h>
#include <stdint.h>
#include <ntstrsafe.h>

#include "../kernel/modules.h"

/*
- Use Udman Spoof Calls to avoid tracing
- Use XOR for strings & signatures
- Use SpoofCall & SpoofFunc Functions
- Dont paste.
*/

extern "C" DRIVER_INITIALIZE DriverEntry;

typedef struct _KNMI_HANDLER_CALLBACK
{
	struct _KNMI_HANDLER_CALLBACK* Next;
	void(*Callback)();
	void* Context;
	void* Handle;
} KNMI_HANDLER_CALLBACK, * PKNMI_HANDLER_CALLBACK;

typedef struct _KAFFINITY_EX
{
	USHORT Count;                                                           //0x0
	USHORT Size;                                                            //0x2
	ULONG Reserved;                                                         //0x4
	ULONGLONG Bitmap[20];                                                   //0x8
} KAFFINITY_EX, * PKAFFINITY_EX;

typedef ULONG KEPROCESSORINDEX;
extern "C" NTSYSAPI BOOLEAN  NTAPI KeInterlockedSetProcessorAffinityEx(PKAFFINITY_EX pAffinity, KEPROCESSORINDEX idxProcessor);

PKNMI_HANDLER_CALLBACK SigscanKiNmiCallbackListHead() {
	uintptr_t ntos_base_address = modules::get_ntos_base_address();

	// nmi_in_progress function (signature)
	char NmiSignature[] = "\x81\x25\x00\x00\x00\x00\x00\x00\x00\x00\xB9\x00\x00\x00\x00"; // use XOR to encrypt this (will get sig scanned by ac)
	char NmiSignatureMask[] = "xx????????x????"; // use XOR to encrypt this (will get sig scanned by ac)
	uintptr_t nmi_in_progress = modules::find_pattern(ntos_base_address,
		NmiSignature,
		NmiSignatureMask);

	return reinterpret_cast<PKNMI_HANDLER_CALLBACK>(nmi_in_progress);
}

PKNMI_HANDLER_CALLBACK KiNmiCallbackListHead = nullptr;
extern "C" NTSTATUS PreventNMIExecution() {
	KiNmiCallbackListHead = SigscanKiNmiCallbackListHead();
	PKNMI_HANDLER_CALLBACK CurrentNMI = KiNmiCallbackListHead;
	while (CurrentNMI) {
		uint8_t* nmi_in_progress = reinterpret_cast<uint8_t*>(KiNmiCallbackListHead);

		while (*nmi_in_progress != 0x48) {
			++nmi_in_progress;
		}

		nmi_in_progress = reinterpret_cast<uint8_t*>(reinterpret_cast<intptr_t>(nmi_in_progress) + 3);

		auto irql = KfRaiseIrql(0); // Use Udman Spoof to not get logged by this

		ULONG cores = KeQueryActiveProcessorCount(NULL); // Use Udman Spoof to not get logged by this

		for (auto i = 0ul; i < cores; ++i) {
			KeInterlockedSetProcessorAffinityEx((PKAFFINITY_EX)nmi_in_progress, i); // Use Udman Spoof to not get logged by this
			InterlockedBitTestAndSet64(reinterpret_cast<LONG64*>(nmi_in_progress), i);
		}

		KeLowerIrql(irql); // Use Udman Spoof to not get logged by this

		CurrentNMI = CurrentNMI->Next;
	}
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS NmiStatus = PreventNMIExecution();
	return NmiStatus;
}