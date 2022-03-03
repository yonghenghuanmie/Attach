#include <Windows.h>
#include <tchar.h>
#define Export
#include "InjectionDll.h"

#pragma data_seg("shared")
TCHAR path[MAX_PATH]={0};
int load=1;
#pragma data_seg()
#pragma comment(linker,"/section:shared,rws")

HINSTANCE hInstance;
BOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hInstance=hModule;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

LRESULT __stdcall HookProc(int code,WPARAM wParam,LPARAM lParam)
{
	HANDLE hevent=OpenEvent(EVENT_ALL_ACCESS,0,_T("Hook"));
	HINSTANCE hmodule;
	if(load)
		hmodule=LoadLibrary(path);
	else
		hmodule=(HINSTANCE)FreeLibrary(GetModuleHandle(path));
	if(hmodule)
		SetEvent(hevent);
	CloseHandle(hevent);
	return CallNextHookEx(0,code,wParam,lParam);
}

HHOOK SetHook(int tid)
{
	return SetWindowsHookEx(WH_GETMESSAGE,HookProc,hInstance,tid);
}

int Unhook(HHOOK hhook)
{
	return UnhookWindowsHookEx(hhook);
}

void SetPathA(char* buffer)
{
#ifdef UNICODE
	MultiByteToWideChar(CP_ACP,0,buffer,-1,path,MAX_PATH);
#else
	_tcscpy_s(path,MAX_PATH,buffer);
#endif // UNICODE
}

void SetPathW(WCHAR* buffer)
{
#ifdef UNICODE
	_tcscpy_s(path,MAX_PATH,buffer);
#else
	WideCharToMultiByte(CP_ACP,0,buffer,-1,path,MAX_PATH,0,0);
#endif // UNICODE
}