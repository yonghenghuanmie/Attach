#include <tchar.h>
#include <stdio.h>
#include <locale.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "..\InjectionDll\InjectionDll.h"
#include "..\Attach\Attach.h"

int Hook(HANDLE hevent,int tid,int time)
{
	int success=0;
	ResetEvent(hevent);
	HHOOK hhook=SetHook(tid);
	PostThreadMessage(tid,WM_NULL,0,0);
	if(WaitForSingleObject(hevent,time)==WAIT_OBJECT_0)
		success=1;
	Unhook(hhook);
	return success;
}

int RemoteThread(HANDLE hprocess,TCHAR* path,int num,int load)
{
	int success=0;
	LPTHREAD_START_ROUTINE function;
	void* address=0;
	int write=1;
	if(load)
	{
		function=(LPTHREAD_START_ROUTINE)LoadLibrary;
		int size=(int)(_tcslen(path)+1)*sizeof(TCHAR);
		address=VirtualAllocEx(hprocess,0,size,MEM_COMMIT,PAGE_READWRITE);
		write=WriteProcessMemory(hprocess,address,path,size,0);
	}
	else
	{
		function=(LPTHREAD_START_ROUTINE)FreeLibrary;
		address=freestruct[num].hmodule;
	}
	if(write)
	{
		HANDLE hthread=CreateRemoteThread(hprocess,0,0,function,address,0,0);
		if(hthread)
		{
			WaitForSingleObject(hthread,INFINITE);
			GetExitCodeThread(hthread,&success);
			CloseHandle(hthread);
		}
	}
	if(load&&address)
		VirtualFreeEx(hprocess,address,0,MEM_RELEASE);
	return success;
}

int jmp(HANDLE hProcess,int pid,TCHAR* path,HANDLE hEvent,int time,int load,int num)
{
	HANDLE hThread=0;
	if(load)
	{
		HANDLE hSnapShotThread=CreateToolhelp32Snapshot(TH32CS_SNAPALL,pid);
		if(hSnapShotThread==(void*)-1)
			return 0;
		THREADENTRY32 te32={sizeof(THREADENTRY32)};
		for(int bool=Thread32First(hSnapShotThread,&te32);bool;bool=Thread32Next(hSnapShotThread,&te32))
			if(hThread=OpenThread(THREAD_ALL_ACCESS,0,te32.th32ThreadID))
				break;
		CloseHandle(hSnapShotThread);
		if(!hThread)
			return 0;
	}
	else
		hThread=OpenThread(THREAD_ALL_ACCESS,0,freestruct[num].tid);
	CONTEXT Context={CONTEXT_CONTROL};
	SuspendThread(hThread);
	if(!GetThreadContext(hThread,&Context))
	{
		ResumeThread(hThread);
		CloseHandle(hThread);
		return 0;
	}
	void* address;
	if(load)
	{
		int size=(int)(_tcslen(path)+1)*sizeof(TCHAR);
		address=VirtualAllocEx(hProcess,0,size,MEM_COMMIT,PAGE_READWRITE);
		if(!address)
		{
			CloseHandle(hThread);
			return 0;
		}
		if(!WriteProcessMemory(hProcess,address,path,size,0))
		{
			VirtualFreeEx(hProcess,address,0,MEM_RELEASE);
			CloseHandle(hThread);
			return 0;
		}
	}
	else
		address=freestruct[num].hmodule;
	Context.Esp-=sizeof(void*);
	WriteProcessMemory(hProcess,(void*)Context.Esp,&address,sizeof(void*),0);
	Context.Esp-=sizeof(void*);
	WriteProcessMemory(hProcess,(void*)Context.Esp,&Context.Eip,sizeof(void*),0);
	Context.Eip=load?((int)LoadLibrary):((int)FreeLibrary);
	SetThreadContext(hThread,&Context);
	ResetEvent(hEvent);
	ResumeThread(hThread);
	int success=0;
	if(WaitForSingleObject(hEvent,time)==WAIT_OBJECT_0)
		success=1;
	VirtualFreeEx(hProcess,address,0,MEM_RELEASE);
	CloseHandle(hThread);
	return success;
}

void Injection(TCHAR* path,int hook,int time,int OSbits64,HANDLE hevent)
{
	HANDLE hsnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
	int successremote=0,successhook=0,count=0,pid=GetCurrentProcessId();
	PROCESSENTRY32 pe32={sizeof(PROCESSENTRY32)};
	for(int boolean=Process32First(hsnapshot,&pe32);boolean;boolean=Process32Next(hsnapshot,&pe32),count++)
	{
		if(pe32.th32ProcessID==pid)
			continue;
		HANDLE hProcess=OpenProcess(PROCESS_ALL_ACCESS,0,pe32.th32ProcessID);
		int wow64;
		if(OSbits64&&hProcess)
		{
			IsWow64Process(hProcess,&wow64);
#ifdef _WIN64
			if(wow64)
			{
				CloseHandle(hProcess);
				continue;
			}
#else
			if(!wow64)
			{
				CloseHandle(hProcess);
				continue;
			}
#endif // _WIN64
		}
		if(hProcess&&RemoteThread(hProcess,path,0,1))
			successremote++;
		else if(hook)
		{
			HANDLE hSnapShotThread=CreateToolhelp32Snapshot(TH32CS_SNAPALL,pe32.th32ProcessID);
			if(hSnapShotThread==(void*)-1)
				continue;
			THREADENTRY32 te32={sizeof(THREADENTRY32)};
			for(int bool=Thread32First(hSnapShotThread,&te32);bool;bool=Thread32Next(hSnapShotThread,&te32))
				if(Hook(hevent,te32.th32ThreadID,time))
				{
					successhook++;
					break;
				}
			CloseHandle(hSnapShotThread);
		}
		if(hProcess)
			CloseHandle(hProcess);
	}
	CloseHandle(hsnapshot);
	_stprintf_s(path,MAX_PATH,_T("共%d个进程,远程线程成功注入%d个进程,线程钩子成功注入%d个进程."),
		count,successremote,successhook);
	MessageBox(0,path,_T("Injection"),MB_OK);
}

int GetAttribute(FILE* file,TCHAR* path,int number)
{
	_ftscanf_s(file,_T("%s"),path,MAX_PATH);
	TCHAR* string=_tcschr(path,_T('='));
	if(string)
	{
		if(number)
			return _ttoi(string+1);
		else if(_tcsicmp(string+1,_T("true"))==0)
			return 1;
	}
	return 0;
}

int Initialize(TCHAR* path,int* global,int* hook,int* time,int* OSbits64,HINSTANCE hInstance)
{
	FILE* file;
	_tsetlocale(LC_ALL,_T(""));
	GetModuleFileName(hInstance,path,MAX_PATH);
	*_tcsrchr(path,_T('\\'))=0;
	SetCurrentDirectory(path);
	if(_tfopen_s(&file,_T("Injection.ini"),_T("r")))//fails
	{
		if(_tfopen_s(&file,_T("Injection.ini"),_T("w")))
		{
			MessageBox(0,_T("无法创建配置文件!"),_T("Injection"),MB_OK|MB_ICONHAND);
			return 0;
		}
		else
		{
			_ftprintf_s(file,_T("AttachAllTheMoudle=false\n\n//若AttachAllTheMoudle为true,则此项为不挂接\
模块.若AttachAllTheMoudle为false,则此项为挂接模块.若AttachAllTheMoudle为false时此项为空,则挂接默认模块.模块间请用;分隔.\nAttachMoudle=\n\n\
GlobalInjection=false\n\n//使用线程钩子注入可能会无法取消注入.\nHook=false\n\n//挂钩等待时间.超时即认为注入失败.\nHooktime=100\n\nOSbits=32\
\n\n//AttachLoadLibrary会挂接LoadLibraryA,LoadLibraryW,LoadLibraryExA,LoadLibraryExW,并将挂接加载模块中的目标函数.\nAttachLoadLibrary=false\n\n\
//挂接GetProcAddress.当被挂接模块使用GetProcAddress获取目标函数地址时,返回挂接函数地址.\nAttachGetProcAddress=true"));
		}
	}
	else
	{
		attachall=GetAttribute(file,path,0);
		_ftscanf_s(file,_T("%s"),path,MAX_PATH);
		_ftscanf_s(file,_T("%s"),path,MAX_PATH);
		TCHAR* string=_tcsrchr(path,_T('='))+1;
		if(string[0])
		{
			int length=(int)_tcslen(string);
			if(string[length-1]!=';')
			{
				string[length]=';';
				string[length+1]=0;
				length++;
			}
			for(TCHAR* change=_tcschr(string,_T(';'));change;change=_tcschr(change+1,_T(';')))
				change[0]=0;
			SetAttachMoudle(string,length+1);
		}
		*global=GetAttribute(file,path,0);
		_ftscanf_s(file,_T("%s"),path,MAX_PATH);
		*hook=GetAttribute(file,path,0);
		_ftscanf_s(file,_T("%s"),path,MAX_PATH);
		*time=GetAttribute(file,path,1);
		if(*time==0)
			*time=100;
		*OSbits64=(GetAttribute(file,path,1)==64);
		_ftscanf_s(file,_T("%s"),path,MAX_PATH);
		loadlibrary=GetAttribute(file,path,0);
		_ftscanf_s(file,_T("%s"),path,MAX_PATH);
		getprocaddress=GetAttribute(file,path,0);
	}
	fclose(file);
	GetCurrentDirectory(MAX_PATH,path);
	_tcscat_s(path,MAX_PATH,_T("\\Attach.dll"));
	SetPath(path);
	return 1;
}
void LoadFree(TCHAR* path,int global,int hook,int time,int OSbits64,TCHAR* lpCmdLine)
{
	HANDLE hevent=CreateEvent(0,1,0,_T("Hook"));
	if(loadcount>0)
	{
		int count=loadcount,successremote=0,successhook=0,i=0;
		load=0;
		for(;freestruct[i].pid;i++)
		{
			if(freestruct[i].hmodule==(HINSTANCE)1)
				continue;
			HANDLE hProcess=OpenProcess(PROCESS_ALL_ACCESS,0,freestruct[i].pid);
			if(hProcess&&RemoteThread(hProcess,0,i,0))
			{
				freestruct[i].hmodule=(HINSTANCE)1;
				successremote++;
			}
			else if(hook&&Hook(hevent,freestruct[i].tid,time))
			{
				freestruct[i].hmodule=(HINSTANCE)1;
				successhook++;
			}
			if(hProcess)
				CloseHandle(hProcess);
		}
		_stprintf_s(path,MAX_PATH,_T("共注入了%d个进程,远程线程撤销注入%d个进程,线程钩子撤销注入%d个进程."),
			count,successremote,successhook);
		MessageBox(0,path,_T("Injection"),MB_OK);
	}
	else
	{
		if(global)
			Injection(path,hook,time,OSbits64,hevent);
		else
		{
			int pid=_ttoi(lpCmdLine);
			HANDLE hProcess=OpenProcess(PROCESS_ALL_ACCESS,0,pid);
			if(hProcess&&RemoteThread(hProcess,path,0,1))
				_stprintf_s(path,MAX_PATH,_T("PID:%d\t远程线程注入成功!"),pid);
			else
				_stprintf_s(path,MAX_PATH,_T("PID:%d\t远程线程注入失败!"),pid);
			if(hProcess)
				CloseHandle(hProcess);
			MessageBox(0,path,_T("Injection"),MB_OK);
		}
	}
	CloseHandle(hevent);
}

int __stdcall _tWinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPTSTR lpCmdLine,int nCmdShow)
{
	TCHAR path[MAX_PATH];
	int global=0,hook=0,time=100,OSbits64=0;
	if(!Initialize(path,&global,&hook,&time,&OSbits64,hInstance))
		return 0;
	InitializeDll();
	LoadFree(path,global,hook,time,OSbits64,lpCmdLine);
	return 0;
}