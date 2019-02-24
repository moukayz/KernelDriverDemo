# KernelDriverDemo
This is a demo Windows driver, which used to learn the internals of Windows.

## Current demos:
- Enum APCs : Enum all APCs (kernel and user mode) of the all threads in **any given process**.
- Enum process/thread/image notify routine callbacks: Enum all callback routines which set by functions like `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine` and `PsSetLoadImageNotifyRoutine`.
- Inject dll by APC: Inject the given dll to the given process by user-mode APC.

## TODO:
To implement user-mode client to test demo driver ( no need to hardcode test code in driver itself )
