#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <ImageHlp.h>
#define Export
#include "Attach.h"

#pragma comment(lib,"ImageHlp")
#pragma data_seg("shared")
DATA attachdata[16]={0};
TCHAR attachmodule[256]={0};
FREESTRUCT freestruct[128]={0};
void* pointer[512]={0};//16*32=512
int loadcount=0,attachall=0,loadlibrary=0,getprocaddress=1,IAT=1;
#pragma data_seg()
#pragma comment(linker,"/section:shared,rws")

char SaveCode[512][13];
int SaveBytes=0;
HINSTANCE __stdcall LoadLibraryAReplace(char* buffer);
HINSTANCE __stdcall LoadLibraryWReplace(WCHAR* buffer);
HINSTANCE __stdcall LoadLibraryExAReplace(char* buffer,HANDLE hfile,DWORD dwFlags);
HINSTANCE __stdcall LoadLibraryExWReplace(WCHAR* buffer,HANDLE hfile,DWORD dwFlags);
FARPROC __stdcall GetProcAddressReplace(HINSTANCE hmodule,char* buffer);
int __stdcall MessageBoxAReplace(HWND hwnd,char* text,char* title,int flag);

void SetAttachMoudleA(char* buffer,int num)
{
#ifdef UNICODE
	MultiByteToWideChar(CP_ACP,0,buffer,num,attachmodule,256);
#else
	memcpy(attachmodule,buffer,num*sizeof(TCHAR));
#endif // UNICODE
}

void SetAttachMoudleW(WCHAR* buffer,int num)
{
#ifdef UNICODE
	memcpy(attachmodule,buffer,num*sizeof(TCHAR));
#else
	WideCharToMultiByte(CP_ACP,0,buffer,num,attachmodule,256,0,0);
#endif // UNICODE
}

void SetData(char* function[16],char* module[16])
{
	for(int i=0;i<16;i++)
	{
		if(function[i])
		{
			memcpy(attachdata[i].function,function[i],sizeof(attachdata[i].function));
			memcpy(attachdata[i].module,module[i],sizeof(attachdata[i].module));
		}
	}
}

char* GetString(int num)
{
	int count=0;
	for(int i=0;i<16;i++)
		for(char* string=attachdata[i].function;string[0];string+=strlen(string)+1,count++)
			if(count==num)
				return string;
	return 0;
}

int GetNum(char* buffer)
{
	int count=0;
	for(int i=0;attachdata[i].module[0]&&i<16;i++)
		for(char* string=attachdata[i].function;string[0];string+=strlen(string)+1,count++)
			if(strcmp(string,buffer)==0)
				return count;
	return 0;
}

int QueryAttach(int id)
{
	TCHAR string[64];
#ifdef UNICODE
	swprintf_s(string,64,_T("%S函数被调用,\"是\"继续调用,\"否\"取消调用."),GetString(id));
#else
	sprintf_s(string,64,_T("%s函数被调用,\"是\"继续调用,\"否\"取消调用."),GetString(id));
#endif // UNICODE
	if(MessageBox(GetActiveWindow(),string,_T("QueryAttach"),MB_YESNO)==IDYES)
		return 1;
	else
		return 0;
}

void SetFunctionPointer()
{
	int i=0;
	if(strcmp(GetString(0),"LoadLibraryA")==0)
	{
		pointer[0]=LoadLibraryAReplace;
		pointer[1]=LoadLibraryWReplace;
		pointer[2]=LoadLibraryExAReplace;
		pointer[3]=LoadLibraryExWReplace;
		i=4;
	}
	if(strcmp(GetString(i),"GetProcAddress")==0)
	{
		pointer[i]=GetProcAddressReplace;
		i++;
	}
	pointer[i+0]=MessageBoxAReplace;
}

void WriteMemory(void* destination,void* source,int bytes)
{
	int protect;
	VirtualProtect(destination,bytes,PAGE_READWRITE,&protect);
	WriteProcessMemory(GetCurrentProcess(),destination,source,bytes,0);
	VirtualProtect(destination,bytes,protect,&protect);
}

void Attach(HINSTANCE hModule,int attach)
{
	int size;
	IMAGE_IMPORT_DESCRIPTOR* image=ImageDirectoryEntryToDataEx(hModule,1,IMAGE_DIRECTORY_ENTRY_IMPORT,&size,0);
	if(image)
	{
		for(;image->Name;image++)
			for(int i=0;attachdata[i].module[0]&&i<16;i++)
				if(_stricmp((char*)((size_t)hModule+image->Name),attachdata[i].module)==0)
					for(IMAGE_THUNK_DATA* thunk=(IMAGE_THUNK_DATA*)((size_t)hModule+image->FirstThunk);thunk->u1.Function;thunk++)
						if(attach)
						{
							for(char* string=attachdata[i].function;string[0];string+=strlen(string)+1)
								if(thunk->u1.Function==(size_t)GetProcAddress(GetModuleHandleA(attachdata[i].module),string))
									WriteMemory(&thunk->u1.Function,&pointer[GetNum(string)],sizeof(void*));
						}
						else
							for(int j=0;pointer[j];j++)
								if(thunk->u1.Function==(size_t)pointer[j])
								{
									void* source=GetProcAddress(GetModuleHandleA(attachdata[i].module),GetString(j));
									WriteMemory(&thunk->u1.Function,&source,sizeof(void*));
								}
	}
}

void GlobalAttach(HINSTANCE hInstance,int attach)
{
	HANDLE hsnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
	MODULEENTRY32 me32={sizeof(MODULEENTRY32)};
	TCHAR* modulestring=_T("");
	if(attachmodule[0])
		modulestring=attachmodule;
	else if(!attachall)
	{
		TCHAR execute[MAX_PATH];
		GetModuleFileName(GetModuleHandle(0),execute,MAX_PATH);
		modulestring=_tcsrchr(execute,_T('\\'))+1;
	}
	TCHAR* start=modulestring;
	for(int boolean=Module32First(hsnapshot,&me32);boolean;boolean=Module32Next(hsnapshot,&me32))
	{
		int skip=0;
		if(me32.hModule==hInstance)
			continue;
		for(modulestring=start;modulestring[0];modulestring+=_tcslen(modulestring)+1)
			if(_tcsicmp(me32.szModule,modulestring)==0)
				if(!attachall)
					Attach(me32.hModule,attach);
				else
				{
					skip=1;
					break;
				}
		if(attachall&&!skip)
			Attach(me32.hModule,attach);
	}
	CloseHandle(hsnapshot);
}

//int Jump()
//{
//	for(int i=0;attachdata[i].module[0]&&i<16;i++)
//		for(char* string=attachdata[i].function;string[0];string+=strlen(string)+1)
//		{
//			int count=0;
//			void* destination=GetProcAddress(GetModuleHandleA(attachdata[i].module),string);
//#ifdef _WIN64
//#else
//			if(SaveBytes==0)
//			SaveBytes=5;
//			char code[5]={0xE9};
//			*(int*)&code[1]=(int)pointer[count]-((int)destination)-5;	//jmp
//#endif // _WIN64
//			memcpy_s(SaveCode[i],6,destination,6);
//			WriteMemory(destination,code,SaveBytes);
//			count++;
//		}
//}

HINSTANCE __stdcall LoadLibraryAReplace(char* buffer)
{
	HINSTANCE hlibrary=LoadLibraryA(buffer);
	if(hlibrary)
		Attach(hlibrary,1);
	return hlibrary;
}

HINSTANCE __stdcall LoadLibraryWReplace(WCHAR* buffer)
{
	HINSTANCE hlibrary=LoadLibraryW(buffer);
	if(hlibrary)
		Attach(hlibrary,1);
	return hlibrary;
}

HINSTANCE __stdcall LoadLibraryExAReplace(char* buffer,HANDLE hfile,DWORD dwFlags)
{
	HINSTANCE hlibrary=LoadLibraryExA(buffer,hfile,dwFlags);
	if(hlibrary)
		Attach(hlibrary,1);
	return hlibrary;
}

HINSTANCE __stdcall LoadLibraryExWReplace(WCHAR* buffer,HANDLE hfile,DWORD dwFlags)
{
	HINSTANCE hlibrary=LoadLibraryExW(buffer,hfile,dwFlags);
	if(hlibrary)
		Attach(hlibrary,1);
	return hlibrary;
}

FARPROC __stdcall GetProcAddressReplace(HINSTANCE hmodule,char* buffer)
{
	int count=0;
	FARPROC address=GetProcAddress(hmodule,buffer);
	for(int i=0;attachdata[i].module[0]&&i<16;i++)
		for(char* string=attachdata[i].function;string[0];string+=strlen(string)+1,count++)
			if(GetProcAddress(GetModuleHandleA(attachdata[i].module),string)==address)
				return pointer[count];
	return address;
}

int GetOrdinal(void* address)
{
	for(int i=0;pointer[i];i++)
		if(pointer[i]==address)
			return i;
	return 0;
}
int __stdcall MessageBoxAReplace(HWND hwnd,char* text,char* title,int flag)
{
	if(QueryAttach(GetOrdinal(MessageBoxAReplace)))
		return MessageBoxA(hwnd,text,title,flag);
	else
		return 0;
}

int CountBytes(char* string)
{
	int i=0;
	for(;string[i];i+=((int)strlen(&string[i]))+1);
	return i;
}

void InitializeDll()
{
	int i=0;
	char* string=attachdata[i].function;
	if(loadlibrary)
	{
		char buffer[]="LoadLibraryA\0LoadLibraryW\0LoadLibraryExA\0LoadLibraryExW";
		int length=sizeof(buffer);
		memcpy_s(string,256,buffer,length);
		string+=length;
		strcpy_s(attachdata[i].module,64,"kernel32.dll");
		i++;
	}
	if(getprocaddress)
	{
		char buffer[]="GetProcAddress";
		int length=sizeof(buffer);
		memcpy_s(string,256,buffer,length);
		string+=length;
		if(i==0)
		{
			strcpy_s(attachdata[i].module,64,"kernel32.dll");
			i++;
		}
	}
	string="MessageBoxA\0";
	memcpy_s(attachdata[i+0].function,256,string,CountBytes(string));
	strcpy_s(attachdata[i+0].module,64,"user32.dll");
	SetFunctionPointer();
}

BOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{
	if(GetModuleHandle(_T("Injection.exe")))
		return 1;
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		loadcount++;
		freestruct[loadcount-1].pid=GetCurrentProcessId();
		freestruct[loadcount-1].tid=GetCurrentThreadId();
		freestruct[loadcount-1].hmodule=hModule;
		GlobalAttach(hModule,1);
		break;
	case DLL_PROCESS_DETACH:
		loadcount--;
		GlobalAttach(hModule,0);
		break;
	}
	return TRUE;
}