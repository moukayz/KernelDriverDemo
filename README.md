# KernelDriverDemo
This is a demo Windows driver, which used to learn the internals of Windows.

## Current demos:
### Enumerate:
- Enum APCs : Enum all APCs (kernel and user mode) of the all threads in **any given process**.
- Enum process/thread/image notify routine callbacks: Enum all callback routines which set by functions like `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine` and `PsSetLoadImageNotifyRoutine`.
- Enum object callbacks: Enum Process/Thread object callbacks registered by `ObRegisterCallbacks` ( callbacks are used to monitor handle creatation/duplication )
- Get kernel base: Get image base address of `ntoskrnl.exe`
### Disable
- Disable notify routine callbacks: Disable all above three callbacks ( callbacks can be removed normally by functions like`PsRemoveCreateThreadNotifyRoutine`)
- Disable object callbacks: Disable above callbacks ( callbacks can be removed normally by `ObUnregisterCallbacks` )
### Inject
- Inject dll by APC: Inject the given dll to the given process by user-mode APC.

## TODO:
To implement user-mode client to test demo driver ( no need to hardcode test code in driver itself )

## ONLY TESTED ON WIN7!!