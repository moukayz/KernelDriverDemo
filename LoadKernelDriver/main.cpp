#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>

VOID ErrorExit(LPCSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s ---- error code %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
	//log_error((LPCSTR)lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

int _cdecl main()
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	printf("Load Driver\n");

	if (hSCManager)
	{
		printf("Create Service\n");
		//if ((hService = OpenService(
		//	(SC_HANDLE)hSCManager,
		//	"Simple Driver",
		//	SERVICE_START | DELETE | SERVICE_STOP)))
		//{
		//	//ControlService(hService, SERVICE_CONTROL_STOP, &ss);
		//	DeleteService(hService);
		//}

		hService = CreateService(
			(SC_HANDLE)hSCManager,
			"Simple Driver",
			"Simple Driver",
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE,
			"C:\\Users\\MOUKA\\Source\\Repos\\KernelDriverDemo\\x64\\Debug\\SimplekmNTDriver.sys",
			NULL, NULL, NULL, NULL, NULL);

		if (!hService)
		{
			printf("Try open service\n");
			
			if (!(hService = OpenService(
				(SC_HANDLE)hSCManager,
				"Simple Driver",
				SERVICE_START | DELETE | SERVICE_STOP)))
				ErrorExit("Cannot create or open service.\n");


		}

		if (hService)
		{
			printf("start service\n");
			if (!StartService(hService, 0, NULL))
			{
				ErrorExit("Cannot start service.\n");
			}

			printf("Press enter to close service\n");
			getchar();
			ControlService(hService, SERVICE_CONTROL_STOP, &ss);
			DeleteService(hService);

			CloseServiceHandle(hService);
		}

		CloseServiceHandle(hSCManager);
		
	}


}