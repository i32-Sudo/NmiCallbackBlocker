# Warning ⚠️
***THERE IS 0 ANTI-CHEAT PROTECTIONS IN THIS PROJECT, PLEASE USE A BASE DRIVER THAT IS ALREADY UNDETECTED, THIS IS JUST A CONCEPT PROJECT.***
# Explenation
The exploit involves scanning for specific signatures in kernel memory, and modifying processor affinity masks to prevent NMIs from executing. This approach employs techniques to avoid detection and tracing.
# Function
1. I do a signature scan for NMI_IN_PROGRESS using 23H2 Signatures for NMI_IN_PROGRESS and import the struct as (PKNMI_HANDLER_CALLBACK) for easy DKOM Modification.
```cpp
	// nmi_in_progress function (signature)
	char NmiSignature[] = "\x81\x25\x00\x00\x00\x00\x00\x00\x00\x00\xB9\x00\x00\x00\x00"; // use XOR to encrypt this (will get sig scanned by ac)
	char NmiSignatureMask[] = "xx????????x????"; // use XOR to encrypt this (will get sig scanned by ac)
	uintptr_t nmi_in_progress = modules::find_pattern(ntos_base_address,
		NmiSignature,
		NmiSignatureMask);

    return reinterpret_cast<PKNMI_HANDLER_CALLBACK>(nmi_in_progress);
```
2. I then after importing the structure loop through the KiNmiCallbackList and change the process affinity of the specific assets to prevent NMI Execution.
```cpp
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
```
# EAC NMI Walker
```cpp
BOOLEAN EAC::NmiCallbackRoutine( PVOID Context, BOOLEAN Handled )
{
	auto* callback_context = reinterpret_cast< EAC_NMI_CALLBACK_CONTEXT* >( Context );
	
	auto* data = &callback_context->data_blocks[ KeGetCurrentProcessorNumberEx( NULL ) ];
	
	if ( !data->gdtr_value.base )
	{
		const auto* current_thread = PsGetCurrentThread();
		__sgdt( &data->gdtr_value );
		data->thread_id = PsGetCurrentThreadId();
		data->thread_process_id = PsGetThreadProcessId( current_thread );
		data->thread_SystemCallNumber = current_thread->SystemCallNumber;
		data->thread_StartAddress = current_thread->StartAddress;
		data->thread_StackLimit = current_thread->StackLimit;
		data->thread_StackBase = current_thread->StackBase;
		data->pcr_HalReserved_8 = KeGetPcr()->HalReserved[ 8 ];
		data->cr3_value = __readcr3();
		data->stack_copy_number_of_bytes = 1024;
		std::memcpy( &data->stack_copy, _AddressOfReturnAddress(), 1024 );
		_InterlockedIncrement( &callback_context->counter );
	}
	
	return TRUE;
}
// Not My Code
```
# Notes
You will need to add & use (x) as this is detected by default for Tracing & Trace Calls (If using standard NtLoad or standard Service Running).
- Udman Spoof Calls to avoid tracing
- XOR for strings & signatures
- SpoofCall & SpoofFunc Functions
# PatchGuard & HVCI
This will trigger PatchGuard Protections and if trying to bypass PatchGuard will trigger HyperGuard High-Level Protections and if you also use HVCI (say in valorant/VGK) This will trigger a BSOD or block the requests to modify the NMI List and nothing will change. I have figured these issues out on my own for my personal driver but if you have a bypass for PatchGuard / HyperGuard and dont use HVCI Protection (for BE/EAC) this will work.
# Contact
If you want an actually good Kernel Level Cheat that is UD My discord is -> `_ambitza`
