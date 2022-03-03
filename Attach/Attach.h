#pragma once
#include "..\Injection\Macro.h"

typedef struct _DATA
{
	char function[256],module[64];
}DATA;

typedef struct _FREESTRUCT
{
	int pid,tid;
	HINSTANCE hmodule;
}FREESTRUCT;

Export void InitializeDll();
Export void SetAttachMoudleA(char* buffer,int num);
Export void SetAttachMoudleW(WCHAR* buffer,int num);
Export FREESTRUCT freestruct[128];
Export int loadcount;
Export int attachall;
Export int loadlibrary;
Export int getprocaddress;
Export int IAT;

#ifdef UNICODE
#define SetAttachMoudle SetAttachMoudleW
#else
#define SetAttachMoudle SetAttachMoudleA
#endif // UNICODE